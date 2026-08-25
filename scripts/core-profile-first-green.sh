#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <candidate-bundle-dir>" >&2
  exit 64
fi
fail() {
  echo "Core candidate conformance failed: $1" >&2
  exit 1
}
: "${RSS_CORE_IMAGE_ID:?RSS_CORE_IMAGE_ID is required}"
: "${RSS_CORE_MIGRATION_IMAGE_ID:?RSS_CORE_MIGRATION_IMAGE_ID is required}"

bundle="$1"
manifest="$bundle/candidate-bundle.json"
[[ "$bundle" = /* && -f "$manifest" && ! -L "$manifest" ]] ||
  fail "bundle must be absolute and contain a plain manifest"

run_key="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
network="rss-core-green-$run_key"
pg="rss-core-pg-$run_key"
redis="rss-core-redis-$run_key"
issuer="rss-core-issuer-$run_key"
server="rss-core-server-$run_key"
extra="rss-core-extra-$run_key"
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/rss-core-green.XXXXXX")"
cleanup() {
  docker rm -f "$extra" "$server" "$issuer" "$redis" "$pg" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/postgres" "$work/redis" "$work/issuer-private" "$work/issuer-public"
chmod 755 "$work" "$work/postgres" "$work/redis" "$work/issuer-private" "$work/issuer-public"

make_tls() {
  local target="$1" dns="$2"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=rss-core-test-ca" \
    -keyout "$target/ca-key.pem" -out "$target/ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$dns" \
    -keyout "$target/server-key.pem" -out "$target/server.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' "$dns" \
    > "$target/server.ext"
  openssl x509 -req -days 1 -sha256 -in "$target/server.csr" \
    -CA "$target/ca.pem" -CAkey "$target/ca-key.pem" -CAcreateserial \
    -extfile "$target/server.ext" -out "$target/server.pem" >/dev/null 2>&1
  chmod 644 "$target/ca.pem" "$target/server.pem" "$target/server-key.pem"
}
make_tls "$work/postgres" postgres
make_tls "$work/redis" redis

openssl ecparam -name prime256v1 -genkey -noout -out "$work/issuer-private/key.pem"
openssl ec -in "$work/issuer-private/key.pem" -pubout -outform DER -out "$work/issuer-private/public.der" 2>/dev/null
python3 - "$work/issuer-private" "$work/issuer-public" <<'PY'
import base64, json, pathlib, subprocess, sys, time, uuid

private = pathlib.Path(sys.argv[1])
public = pathlib.Path(sys.argv[2])
point = (private / "public.der").read_bytes()[-65:]
if len(point) != 65 or point[0] != 4:
    raise SystemExit("unexpected P-256 public key encoding")
enc = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
kid = "core-first-green-es256"
(public / "jwks.json").write_text(json.dumps({"keys": [{
    "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
    "x": enc(point[1:33]), "y": enc(point[33:65])
}]}) + "\n")
now = int(time.time())
tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
user = "11111111-1111-4111-8111-111111111111"
sid = "22222222-2222-4222-8222-222222222222"
header = enc(json.dumps({"alg": "ES256", "typ": "at+jwt", "kid": kid}, separators=(",", ":")).encode())
claims = {
    "sub": user, "iat": now, "exp": now + 600, "token_use": "access",
    "iss": "http://oidc:8000/", "aud": "rss-core", "kind": "user",
    "tenant_id": tenant, "sid": sid, "jti": str(uuid.uuid4()),
    "auth_time": now, "authn_epoch": 0,
}
payload = enc(json.dumps(claims, separators=(",", ":")).encode())
signed = f"{header}.{payload}".encode()
der = subprocess.run(
    ["openssl", "dgst", "-sha256", "-sign", str(private / "key.pem")],
    input=signed, check=True, stdout=subprocess.PIPE,
).stdout
def der_len(data, offset):
    first = data[offset]
    if first < 128:
        return first, offset + 1
    width = first & 127
    return int.from_bytes(data[offset + 1:offset + 1 + width], "big"), offset + 1 + width
if der[0] != 0x30:
    raise SystemExit("unexpected ECDSA signature")
_, pos = der_len(der, 1)
parts = []
for _ in range(2):
    if der[pos] != 0x02:
        raise SystemExit("unexpected ECDSA integer")
    size, pos = der_len(der, pos + 1)
    value = der[pos:pos + size]
    pos += size
    parts.append(value.lstrip(b"\0").rjust(32, b"\0"))
(private / "token").write_text(f"{header}.{payload}.{enc(b''.join(parts))}\n")
(private / "facts").write_text(f"NOW={now}\nTENANT={tenant}\nUSER_ID={user}\nSID={sid}\n")
PY
# shellcheck disable=SC1091
source "$work/issuer-private/facts"
TARGET_TENANT="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
TARGET_USER_ID="33333333-3333-4333-8333-333333333333"

docker network create "$network" >/dev/null
docker run -d --name "$pg" --network "$network" --network-alias postgres \
  -e POSTGRES_PASSWORD=owner_pw -e POSTGRES_DB=rss \
  -v "$work/postgres:/rss-tls:ro" postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382 \
  sh -ec 'cp /rss-tls/server.pem /tmp/pg-server.pem; cp /rss-tls/server-key.pem /tmp/pg-server-key.pem; cp /rss-tls/ca.pem /tmp/pg-ca.pem; chown postgres:postgres /tmp/pg-server* /tmp/pg-ca.pem; chmod 600 /tmp/pg-server-key.pem; exec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/pg-server.pem -c ssl_key_file=/tmp/pg-server-key.pem -c ssl_ca_file=/tmp/pg-ca.pem' >/dev/null
for _ in $(seq 1 40); do
  docker exec "$pg" pg_isready -U postgres -d rss >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$pg" pg_isready -U postgres -d rss >/dev/null

docker exec -i "$pg" psql -v ON_ERROR_STOP=1 -U postgres -d rss <<'SQL'
DO $$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'rss_app','rss_app_read','rss_projection_reader','rss_projection_operator',
    'rss_saga_operator','rss_l2_dr_recovery_auditor','rss_l2_dr_recovery_executor',
    'rss_dlx_archiver','rss_dlx_verifier','rss_dlx_purger'
  ] LOOP
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT', role_name, role_name || '_pw');
    END IF;
  END LOOP;
END $$;
SQL

printf 'postgresql://postgres:owner_pw@postgres:5432/rss?sslmode=verify-full&sslrootcert=/run/rss/pg-ca.pem\n' > "$work/migration-url"
chmod 644 "$work/migration-url"
docker run --rm --network "$network" \
  -e RSS_PG_DATABASE_URL_FILE=/run/rss/migration-url \
  -v "$work/migration-url:/run/rss/migration-url:ro" \
  -v "$work/postgres/ca.pem:/run/rss/pg-ca.pem:ro" \
  "$RSS_CORE_MIGRATION_IMAGE_ID" postgres migrate-all

docker exec -i "$pg" psql -v ON_ERROR_STOP=1 -U postgres -d rss \
  -v tenant="$TENANT" -v user_id="$USER_ID" -v sid="$SID" -v issued="$NOW" <<'SQL'
BEGIN;
SET CONSTRAINTS ALL DEFERRED;
INSERT INTO credentials
  (tenant_id, user_id, login, password_hash, version, failure_count, created_at)
VALUES (:'tenant'::uuid, :'user_id'::uuid, 'core-inventory-reader',
        'not-used-by-conformance', 1, 0, now());
INSERT INTO account_security_states
  (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at)
VALUES (:'tenant'::uuid, :'user_id'::uuid, 'active', 0, 1, now(), now());
INSERT INTO auth_grants
  (tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue, status, expires_at, created_at)
VALUES (:'tenant'::uuid, :'sid', :'user_id'::uuid, to_timestamp(:'issued'::bigint), 0,
        'active', to_timestamp(:'issued'::bigint) + interval '10 minutes', to_timestamp(:'issued'::bigint));
SELECT set_config('rss.tenant_id', :'tenant', false);
SELECT * FROM rss_record_role_revision(
  'core-inventory-reader', 'Core inventory reader', ARRAY['runtime:inventory:read']::text[],
  :'user_id'::uuid, 'user');
INSERT INTO role_bindings (tenant_id, role_id, subject)
VALUES (:'tenant'::uuid, 'core-inventory-reader', :'user_id');
COMMIT;
SQL

docker exec -i "$pg" psql -v ON_ERROR_STOP=1 -U postgres -d rss \
  -v tenant="$TARGET_TENANT" -v user_id="$TARGET_USER_ID" <<'SQL'
BEGIN;
SET CONSTRAINTS ALL DEFERRED;
INSERT INTO credentials
  (tenant_id, user_id, login, password_hash, version, failure_count, created_at)
VALUES (:'tenant'::uuid, :'user_id'::uuid, 'core-rls-target', 'not-used-by-conformance', 1, 0, now());
INSERT INTO account_security_states
  (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at)
VALUES (:'tenant'::uuid, :'user_id'::uuid, 'active', 0, 1, now(), now());
COMMIT;
SQL

docker run -d --name "$redis" --network "$network" --network-alias redis \
  -v "$work/redis:/rss-tls:ro" redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf redis-server \
  --port 0 --tls-port 6379 --tls-cert-file /rss-tls/server.pem \
  --tls-key-file /rss-tls/server-key.pem --tls-ca-cert-file /rss-tls/ca.pem \
  --tls-auth-clients no >/dev/null
docker run -d --name "$issuer" --network "$network" --network-alias oidc \
  -v "$work/issuer-public:/srv:ro" python:3.13-alpine@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d python3 -m http.server 8000 -d /srv >/dev/null
for _ in $(seq 1 20); do
  docker exec "$redis" redis-cli --tls --cacert /rss-tls/ca.pem PING 2>/dev/null | grep -qx PONG && break
  sleep 1
done
docker exec "$redis" redis-cli --tls --cacert /rss-tls/ca.pem PING | grep -qx PONG
for _ in $(seq 1 20); do
  docker exec "$issuer" wget -qO- http://127.0.0.1:8000/jwks.json >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$issuer" wget -qO- http://127.0.0.1:8000/jwks.json | jq -e '.keys | length == 1' >/dev/null
for secret_path in key.pem token facts; do
  [[ "$(docker exec "$issuer" wget -S -O /dev/null "http://127.0.0.1:8000/$secret_path" 2>&1 | awk '/HTTP\// {code=$2} END {print code}')" == 404 ]]
done
docker exec "$redis" wget -qO- http://oidc:8000/jwks.json > "$work/server-jwks.json"
jq -e '.keys | length == 1' "$work/server-jwks.json" >/dev/null

cat > "$work/serving-secrets.json" <<'JSON'
{"auditChainKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pgPassword":"rss_app_pw","pgReadPassword":"rss_app_read_pw","redisUrl":"rediss://redis:6379"}
JSON
chmod 644 "$work/serving-secrets.json" "$work/server-jwks.json"

server_args=(
  --name "$server" --network "$network"
  -p 127.0.0.1:18082:8082 -p 127.0.0.1:18083:8083
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges
  -v "$work/serving-secrets.json:/var/run/rss/secrets/serving-secret-bundle:ro"
  -v "$work/postgres/ca.pem:/run/rss/pg-ca.pem:ro"
  -v "$work/redis/ca.pem:/run/rss/redis-ca.pem:ro"
  -v "$work/server-jwks.json:/run/rss/jwks.json:ro"
  -e RSS_RUNTIME_PLAN_KIND=core -e RSS_TOPOLOGY=durable-shared
  -e RSS_LISTENER_ALLOW_PLAINTEXT=dev-container
  -e RSS_ADMIN_LISTEN_ADDR=0.0.0.0:8082 -e RSS_HEALTH_LISTEN_ADDR=0.0.0.0:8083
  -e RSS_PRIMARY_TOKEN_PROFILE=rss-access -e RSS_ADMIN_TOKEN_PROFILE=rss-access
  -e RSS_INTERNAL_AUTH_SCHEME=mtls -e RSS_HTTP_SERVER_REQUEST_BUDGET_MS=30000
  -e RSS_PG_HOST=postgres -e RSS_PG_PORT=5432 -e RSS_PG_DATABASE=rss
  -e RSS_PG_USERNAME=rss_app -e RSS_PG_READ_USERNAME=rss_app_read
  -e RSS_PG_MAX_CONNECTIONS=3 -e RSS_PG_READ_MAX_CONNECTIONS=3
  -e RSS_PG_SSL_ROOT_CERT_PATH=/run/rss/pg-ca.pem
  -e RSS_REDIS_CA_CERT_PEM_PATH=/run/rss/redis-ca.pem
  -e RSS_ACCESS_TOKEN_ISSUER=http://oidc:8000/ -e RSS_ACCESS_TOKEN_AUDIENCE=rss-core
  -e RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID=core-first-green-es256
  -e RSS_ACCESS_TOKEN_TTL_SECS=900 -e RSS_ACCESS_TOKEN_JWKS_PATH=/run/rss/jwks.json
  -e RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS=5
  -e RSS_AUTH_GRANT_SWEEP_INTERVAL_MS=300000
)
docker run -d "${server_args[@]}" "$RSS_CORE_IMAGE_ID" >/dev/null
for _ in $(seq 1 45); do
  curl -fsS http://127.0.0.1:18083/health/v1/readyz >/dev/null 2>&1 && break
  if ! docker inspect -f '{{.State.Running}}' "$server" 2>/dev/null | grep -qx true; then
    docker logs "$server" >&2
    exit 1
  fi
  sleep 1
done
curl -fsS http://127.0.0.1:18083/health/v1/readyz >/dev/null

token="$(cat "$work/issuer-private/token")"
inventory="$work/inventory.json"
curl -fsS -H "Authorization: Bearer $token" \
  http://127.0.0.1:18082/api/v1/runtime/inventory > "$inventory"
jq -e --slurpfile bundle "$manifest" '
  .data.schemaVersion == 3 and
  .data.officialProfile.profile == "core" and
  .data.officialProfile.configDigest == $bundle[0].profiles[0].configDigest and
  .data.assemblyLockDigest == $bundle[0].profiles[0].assemblyLockDigest and
  .data.runtimePlanFingerprint == $bundle[0].profiles[0].runtimePlanFingerprint and
  .data.officialProfile.routes == $bundle[0].profiles[0].closure.routes and
  .data.officialProfile.workers == $bundle[0].profiles[0].closure.workers and
  .data.officialProfile.probes == $bundle[0].profiles[0].closure.probes and
  ([.data.listeners[].id] | sort) == $bundle[0].profiles[0].closure.listeners and
  ([.data.providerPosture[].id] | sort) == $bundle[0].profiles[0].closure.providers
' "$inventory" >/dev/null

status="$(curl -sS -o "$work/denied.json" -w '%{http_code}' \
  -H "Authorization: Bearer $token" \
  "http://127.0.0.1:18082/api/v1/audit/tenants/$TARGET_TENANT/entries")"
[[ "$status" == 403 ]] || fail "cross-tenant Audit request did not return 403"
status="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${token%?}x" \
  http://127.0.0.1:18082/api/v1/runtime/inventory)"
[[ "$status" == 401 ]] || fail "invalid access token did not return 401"

audit_count="$(docker exec "$pg" psql -Atq -U postgres -d rss -c \
  "SELECT count(*) FROM auth_audit_events WHERE principal_id='$USER_ID' AND principal_kind='user' AND principal_tenant='$TENANT'::uuid AND resource_kind='audit_entries' AND resource_id='$TARGET_TENANT' AND action='audit:list-cross-tenant' AND outcome='failure' AND failure_reason='forbidden'")"
[[ "$audit_count" == 1 ]] || fail "Audit LocalTx did not commit exactly one denial event"
docker exec -i "$pg" psql -v ON_ERROR_STOP=1 -Atq -U postgres -d rss <<SQL | paste -sd, | grep -qx '1,0'
BEGIN;
SET LOCAL ROLE rss_app;
SET LOCAL rss.tenant_id = '$TARGET_TENANT';
SELECT count(*) FROM account_security_states WHERE tenant_id='$TARGET_TENANT'::uuid;
ROLLBACK;
BEGIN;
SET LOCAL ROLE rss_app;
SET LOCAL rss.tenant_id = '$TENANT';
SELECT count(*) FROM account_security_states WHERE tenant_id='$TARGET_TENANT'::uuid;
ROLLBACK;
SQL

docker stop "$server" >/dev/null
docker rm "$server" >/dev/null
if timeout 20s docker run --name "$extra" \
  "${server_args[@]:2}" -e RSS_AMQP_CA_CERT_PEM_PATH=/run/rss/forbidden-amqp.pem \
  "$RSS_CORE_IMAGE_ID"; then
  echo "Core accepted forbidden Eventing configuration" >&2
  exit 1
fi
[[ "$(docker inspect -f '{{.State.Running}}' "$extra")" == false ]]
docker logs "$extra" 2>&1 | grep -q 'RSS_AMQP_CA_CERT_PEM_PATH'

printf '%s\n' 'Core candidate real-stack conformance passed'
