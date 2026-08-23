#![doc = "Safe JSON-only control CLI for device certificate rotation."]

use std::{
    fs,
    io::{self, Read},
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Args, Parser, Subcommand};
use futures_util::StreamExt;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use openidconnect::PkceCodeChallenge;
use reqwest::{
    Client, Method, StatusCode,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use rotation_model::{KeyUsage, RotationPolicy};
use rss_device_security_client::{
    Diagnostic, DiagnosticKind, PolicyResponse, StatusResponse, decode_policy_response,
    decode_status_response, prepare_policy_put, prepare_status_get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use url::Url;
use uuid::Uuid;

pub const LOGIN_TIMEOUT: Duration = Duration::from_mins(2);
pub const API_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Parser, Debug)]
#[command(name = "rotation-control", version, disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Login(AuthArgs),
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Rotate(RotateArgs),
    Status(StatusArgs),
    Audit(AuditArgs),
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    Check(PolicyCheckArgs),
}

#[derive(Args, Clone, Debug)]
struct AuthArgs {
    #[arg(long)]
    issuer: Url,
    #[arg(long, default_value = "rotation-control")]
    client_id: String,
    #[arg(long)]
    tenant_id: String,
    #[arg(long, default_value = "http://127.0.0.1:8765/callback")]
    redirect_uri: Url,
}

#[derive(Args, Debug)]
struct PolicyCheckArgs {
    #[arg(long)]
    input: PathBuf,
}

#[derive(Args, Debug)]
struct RotateArgs {
    #[command(flatten)]
    auth: AuthArgs,
    #[arg(long)]
    rss_base_url: Url,
    #[arg(long)]
    device_id: Uuid,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    expected_generation: u64,
    #[arg(long)]
    idempotency_key: Option<Uuid>,
}

#[derive(Args, Debug)]
struct StatusArgs {
    #[command(flatten)]
    auth: AuthArgs,
    #[arg(long)]
    rss_base_url: Url,
    #[arg(long)]
    device_id: Uuid,
}

#[derive(Args, Debug)]
struct AuditArgs {
    #[arg(long)]
    input: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyInput {
    key_usages: Vec<UsageInput>,
    renew_before_seconds: u64,
    #[serde(default)]
    sans: Vec<String>,
    validity_seconds: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum UsageInput {
    ClientAuth,
    ServerAuth,
}

impl TryFrom<PolicyInput> for RotationPolicy {
    type Error = AppError;
    fn try_from(value: PolicyInput) -> Result<Self, Self::Error> {
        let usages = value
            .key_usages
            .into_iter()
            .map(|usage| match usage {
                UsageInput::ClientAuth => KeyUsage::ClientAuth,
                UsageInput::ServerAuth => KeyUsage::ServerAuth,
            })
            .collect();
        RotationPolicy::try_new(
            usages,
            value.renew_before_seconds,
            value.sans,
            value.validity_seconds,
        )
        .map_err(|_| AppError::input("invalid_policy"))
    }
}

#[derive(Clone)]
struct TokenSet {
    access_token: String,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TokenSet([REDACTED])")
    }
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct TokenWire {
    access_token: String,
    id_token: String,
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    aud: Audience,
    exp: u64,
    nonce: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[derive(Debug)]
pub struct AppError {
    code: &'static str,
    class: ErrorClass,
    request_id: Option<String>,
    retryable: bool,
}

#[derive(Clone, Copy, Debug)]
enum ErrorClass {
    Input,
    Auth,
    Typed,
    Transport,
    Untrusted,
}

impl AppError {
    fn input(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Input,
            request_id: None,
            retryable: false,
        }
    }
    fn auth(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Auth,
            request_id: None,
            retryable: false,
        }
    }
    fn transport(code: &'static str, retryable: bool) -> Self {
        Self {
            code,
            class: ErrorClass::Transport,
            request_id: None,
            retryable,
        }
    }
    fn untrusted(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Untrusted,
            request_id: None,
            retryable: false,
        }
    }
    fn from_diagnostic(value: &Diagnostic) -> Self {
        let class = match value.kind() {
            DiagnosticKind::Unauthorized | DiagnosticKind::Forbidden => ErrorClass::Auth,
            DiagnosticKind::Validation | DiagnosticKind::NotFound | DiagnosticKind::Conflict => {
                ErrorClass::Typed
            }
            DiagnosticKind::RateLimited | DiagnosticKind::Upstream => ErrorClass::Transport,
            DiagnosticKind::Malformed | DiagnosticKind::UnknownStatus => ErrorClass::Untrusted,
        };
        Self {
            code: value.kind().code(),
            class,
            request_id: value.request_id().map(ToOwned::to_owned),
            retryable: value.retryable(),
        }
    }
    fn exit_code(&self) -> i32 {
        match self.class {
            ErrorClass::Input => 2,
            ErrorClass::Auth => 3,
            ErrorClass::Typed => 4,
            ErrorClass::Transport => 5,
            ErrorClass::Untrusted => 6,
        }
    }
    fn render(&self) -> Value {
        json!({"schemaVersion":"1","outcome":"error","diagnostic":{"category":match self.class { ErrorClass::Input => "input", ErrorClass::Auth => "auth", ErrorClass::Typed => "typed", ErrorClass::Transport => "transport", ErrorClass::Untrusted => "untrusted" },"code":self.code,"retryable":self.retryable,"requestId":self.request_id}})
    }
}

#[must_use]
pub fn main_entry() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            println!(
                "{}",
                AppError::input(if error.use_stderr() {
                    "invalid_cli"
                } else {
                    "cli_help"
                })
                .render()
            );
            return 2;
        }
    };
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        println!(
            "{}",
            AppError::transport("runtime_unavailable", false).render()
        );
        return 5;
    };
    match runtime.block_on(run(cli)) {
        Ok(output) => {
            println!("{output}");
            0
        }
        Err(error) => {
            println!("{}", error.render());
            error.exit_code()
        }
    }
}

async fn run(cli: Cli) -> Result<Value, AppError> {
    match cli.command {
        Command::Login(auth) => {
            let _ = login(&auth).await?;
            Ok(
                json!({"schemaVersion":"1","operation":"login","outcome":"authenticated","tokenPersisted":false}),
            )
        }
        Command::Policy {
            command: PolicyCommand::Check(args),
        } => {
            let policy = read_policy(&args.input)?;
            Ok(
                json!({"schemaVersion":"1","operation":"policy.check","outcome":"valid","validitySeconds":policy.validity_seconds(),"renewBeforeSeconds":policy.renew_before_seconds(),"keyUsageCount":policy.key_usages().len(),"sanCount":policy.sans().len()}),
            )
        }
        Command::Rotate(args) => rotate(args).await,
        Command::Status(args) => status(args).await,
        Command::Audit(args) => audit(&args.input),
    }
}

fn read_policy(path: &PathBuf) -> Result<RotationPolicy, AppError> {
    let bytes = fs::read(path).map_err(|_| AppError::input("input_unreadable"))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(AppError::input("input_oversize"));
    }
    let input: PolicyInput =
        serde_json::from_slice(&bytes).map_err(|_| AppError::input("invalid_policy_json"))?;
    input.try_into()
}

fn secure_remote_url(url: &Url, allow_loopback_http: bool) -> Result<(), AppError> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.scheme() == "http" && allow_loopback_http && loopback {
        Ok(())
    } else {
        Err(AppError::input("plaintext_remote_forbidden"))
    }
}

fn client() -> Result<Client, AppError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(API_TIMEOUT)
        .build()
        .map_err(|_| AppError::transport("http_client_unavailable", false))
}

async fn login(auth: &AuthArgs) -> Result<TokenSet, AppError> {
    secure_remote_url(&auth.issuer, false)?;
    secure_remote_url(&auth.redirect_uri, true)?;
    let callback_host = auth
        .redirect_uri
        .host_str()
        .ok_or_else(|| AppError::input("invalid_redirect"))?;
    if callback_host
        .parse::<IpAddr>()
        .ok()
        .is_none_or(|ip| !ip.is_loopback())
    {
        return Err(AppError::input("redirect_not_loopback"));
    }
    let discovery_url = auth
        .issuer
        .join(".well-known/openid-configuration")
        .map_err(|_| AppError::input("invalid_issuer"))?;
    let http = client()?;
    let discovery: Discovery = fetch_json(&http, discovery_url, LOGIN_TIMEOUT)
        .await
        .map_err(|_| AppError::auth("discovery_failed"))?;
    if discovery.issuer.trim_end_matches('/') != auth.issuer.as_str().trim_end_matches('/') {
        return Err(AppError::auth("issuer_mismatch"));
    }
    let authorization_endpoint = Url::parse(&discovery.authorization_endpoint)
        .map_err(|_| AppError::auth("invalid_discovery"))?;
    let token_endpoint =
        Url::parse(&discovery.token_endpoint).map_err(|_| AppError::auth("invalid_discovery"))?;
    let jwks_uri =
        Url::parse(&discovery.jwks_uri).map_err(|_| AppError::auth("invalid_discovery"))?;
    secure_remote_url(&authorization_endpoint, false)?;
    secure_remote_url(&token_endpoint, false)?;
    secure_remote_url(&jwks_uri, false)?;
    let state = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut authorize = authorization_endpoint;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &auth.client_id)
        .append_pair("redirect_uri", auth.redirect_uri.as_str())
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", challenge.as_str())
        .append_pair("code_challenge_method", "S256");
    let listener = TcpListener::bind((
        callback_host,
        auth.redirect_uri
            .port_or_known_default()
            .ok_or_else(|| AppError::input("invalid_redirect"))?,
    ))
    .await
    .map_err(|_| AppError::auth("callback_bind_failed"))?;
    webbrowser::open(authorize.as_str()).map_err(|_| AppError::auth("browser_launch_failed"))?;
    let code = timeout(
        LOGIN_TIMEOUT,
        receive_callback(listener, &auth.redirect_uri, &state),
    )
    .await
    .map_err(|_| AppError::auth("login_timeout"))??;
    let response = http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", auth.redirect_uri.as_str()),
            ("client_id", auth.client_id.as_str()),
            ("code_verifier", verifier.secret()),
        ])
        .send()
        .await
        .map_err(|_| AppError::auth("token_exchange_failed"))?;
    if response.status() != StatusCode::OK {
        return Err(AppError::auth("token_exchange_rejected"));
    }
    let token: TokenWire = bounded_json(response)
        .await
        .map_err(|_| AppError::auth("token_response_invalid"))?;
    let jwks: JwkSet = fetch_json(&http, jwks_uri, LOGIN_TIMEOUT)
        .await
        .map_err(|_| AppError::auth("jwks_failed"))?;
    validate_id_token(&token.id_token, &jwks, auth, &nonce)?;
    Ok(TokenSet {
        access_token: token.access_token,
    })
}

async fn receive_callback(
    listener: TcpListener,
    redirect: &Url,
    expected_state: &str,
) -> Result<String, AppError> {
    let (mut socket, _) = listener
        .accept()
        .await
        .map_err(|_| AppError::auth("callback_failed"))?;
    let mut request = vec![0_u8; 8192];
    let count = socket
        .read(&mut request)
        .await
        .map_err(|_| AppError::auth("callback_failed"))?;
    let first = std::str::from_utf8(&request[..count])
        .map_err(|_| AppError::auth("callback_invalid"))?
        .lines()
        .next()
        .ok_or_else(|| AppError::auth("callback_invalid"))?;
    let target = first
        .strip_prefix("GET ")
        .and_then(|value| value.split_once(' ').map(|pair| pair.0))
        .ok_or_else(|| AppError::auth("callback_invalid"))?;
    let callback = redirect
        .join(target)
        .map_err(|_| AppError::auth("callback_invalid"))?;
    if callback.path() != redirect.path() {
        return Err(AppError::auth("callback_invalid"));
    }
    let params = callback
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    if params.get("state").map(std::convert::AsRef::as_ref) != Some(expected_state) {
        return Err(AppError::auth("state_mismatch"));
    }
    let code = params
        .get("code")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::auth("authorization_rejected"))?
        .to_string();
    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nAuthentication complete.").await;
    Ok(code)
}

fn validate_id_token(
    token: &str,
    jwks: &JwkSet,
    auth: &AuthArgs,
    nonce: &str,
) -> Result<(), AppError> {
    let header = decode_header(token).map_err(|_| AppError::auth("id_token_invalid"))?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::auth("id_token_algorithm"));
    }
    let kid = header
        .kid
        .ok_or_else(|| AppError::auth("id_token_key_missing"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| AppError::auth("id_token_key_unknown"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| AppError::auth("id_token_key_invalid"))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_issuer(&[auth.issuer.as_str()]);
    let claims = decode::<IdClaims>(token, &key, &validation)
        .map_err(|_| AppError::auth("id_token_invalid"))?
        .claims;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::auth("clock_invalid"))?
        .as_secs();
    validate_claims(&claims, auth, nonce, now)
}

fn validate_claims(
    claims: &IdClaims,
    auth: &AuthArgs,
    nonce: &str,
    now: u64,
) -> Result<(), AppError> {
    if claims.iss.trim_end_matches('/') != auth.issuer.as_str().trim_end_matches('/') {
        return Err(AppError::auth("issuer_mismatch"));
    }
    if claims.exp <= now {
        return Err(AppError::auth("token_expired"));
    }
    if !claims.aud.contains(&auth.client_id) {
        return Err(AppError::auth("audience_mismatch"));
    }
    if claims.nonce != nonce {
        return Err(AppError::auth("nonce_mismatch"));
    }
    if claims.tenant_id != auth.tenant_id {
        return Err(AppError::auth("tenant_mismatch"));
    }
    Ok(())
}

async fn rotate(args: RotateArgs) -> Result<Value, AppError> {
    secure_remote_url(&args.rss_base_url, true)?;
    let policy = read_policy(&args.input)?;
    let token = login(&args.auth).await?;
    let request_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let prepared = prepare_policy_put(
        args.device_id,
        args.expected_generation,
        args.idempotency_key.unwrap_or_else(Uuid::new_v4),
        &policy,
    )
    .map_err(|_| AppError::input("invalid_policy"))?;
    let response = send_api(
        &args.rss_base_url,
        &prepared,
        &token,
        &args.auth.tenant_id,
        request_id,
        correlation_id,
    )
    .await?;
    match decode_policy_response(response.0, &response.1) {
        PolicyResponse::Accepted(value) => Ok(
            json!({"schemaVersion":"1","operation":"rotate","outcome":"accepted","requestId":request_id,"correlationId":correlation_id,"authorizationReceiptId":value.receipt_id(),"acceptedGeneration":value.generation(),"condition":value.condition()}),
        ),
        PolicyResponse::Rejected(error) => Err(AppError::from_diagnostic(&error)),
    }
}

async fn status(args: StatusArgs) -> Result<Value, AppError> {
    secure_remote_url(&args.rss_base_url, true)?;
    let token = login(&args.auth).await?;
    let request_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let prepared = prepare_status_get(args.device_id);
    let response = send_api(
        &args.rss_base_url,
        &prepared,
        &token,
        &args.auth.tenant_id,
        request_id,
        correlation_id,
    )
    .await?;
    match decode_status_response(response.0, &response.1) {
        StatusResponse::Observed(value) => Ok(
            json!({"schemaVersion":"1","operation":"status","outcome":"observed","requestId":request_id,"correlationId":correlation_id,"desiredGeneration":value.desired_generation,"authorizationReceiptId":value.authorization_receipt_id,"observedGeneration":value.observed_generation,"activeCommand":value.active_command.map(|item| json!({"fenceEpoch":item.fence_epoch,"state":item.state})),"conditions":value.conditions.into_iter().map(|item| json!({"observedGeneration":item.observed_generation,"reason":item.reason,"status":item.status,"type":item.type_,"lastTransitionAt":item.last_transition_at})).collect::<Vec<_>>() }),
        ),
        StatusResponse::Rejected(error) => Err(AppError::from_diagnostic(&error)),
    }
}

async fn send_api(
    base: &Url,
    prepared: &rss_device_security_client::PreparedRequest,
    token: &TokenSet,
    tenant: &str,
    request_id: Uuid,
    correlation_id: Uuid,
) -> Result<(u16, Vec<u8>), AppError> {
    let url = base
        .join(prepared.path().trim_start_matches('/'))
        .map_err(|_| AppError::input("invalid_rss_url"))?;
    let method = Method::from_bytes(prepared.method().as_bytes())
        .map_err(|_| AppError::untrusted("invalid_operation"))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.access_token))
            .map_err(|_| AppError::auth("token_invalid"))?,
    );
    headers.insert(
        "x-tenant-id",
        HeaderValue::from_str(tenant).map_err(|_| AppError::input("invalid_tenant"))?,
    );
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("UUID header"),
    );
    headers.insert(
        "x-correlation-id",
        HeaderValue::from_str(&correlation_id.to_string()).expect("UUID header"),
    );
    let http = client()?;
    let mut request = http.request(method, url).headers(headers);
    if let Some(body) = prepared.body() {
        request = request
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_vec());
    }
    let response = request
        .send()
        .await
        .map_err(|_| AppError::transport("request_failed", true))?;
    let status = response.status().as_u16();
    let body = bounded_bytes(response).await?;
    Ok((status, body))
}

async fn bounded_bytes(response: reqwest::Response) -> Result<Vec<u8>, AppError> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(AppError::untrusted("response_oversize"));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::transport("response_read_failed", true))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(AppError::untrusted("response_oversize"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn bounded_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, AppError> {
    let bytes = bounded_bytes(response).await?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::untrusted("malformed_json"))
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(
    http: &Client,
    url: Url,
    limit: Duration,
) -> Result<T, AppError> {
    let response = timeout(limit, http.get(url).send())
        .await
        .map_err(|_| AppError::transport("request_timeout", true))?
        .map_err(|_| AppError::transport("request_failed", true))?;
    if response.status() != StatusCode::OK {
        return Err(AppError::transport("upstream_rejected", false));
    }
    bounded_json(response).await
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RotateRecord {
    schema_version: String,
    operation: String,
    outcome: String,
    request_id: Uuid,
    correlation_id: Uuid,
    authorization_receipt_id: Uuid,
    accepted_generation: u64,
    condition: String,
}

fn audit(input: &str) -> Result<Value, AppError> {
    let mut bytes = Vec::new();
    if input == "-" {
        io::stdin()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| AppError::input("input_unreadable"))?;
    } else {
        bytes = fs::read(input).map_err(|_| AppError::input("input_unreadable"))?;
    }
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(AppError::input("input_oversize"));
    }
    let record: RotateRecord =
        serde_json::from_slice(&bytes).map_err(|_| AppError::input("invalid_rotate_record"))?;
    if record.schema_version != "1"
        || record.operation != "rotate"
        || record.outcome != "accepted"
        || record.accepted_generation == 0
        || !matches!(record.condition.as_str(), "Reconciling" | "PendingDevice")
    {
        return Err(AppError::input("invalid_rotate_record"));
    }
    Ok(
        json!({"schemaVersion":"1","operation":"audit","outcome":"validated","requestId":record.request_id,"correlationId":record.correlation_id,"authorizationReceiptId":record.authorization_receipt_id,"acceptedGeneration":record.accepted_generation,"durableAuditQueried":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    fn auth() -> AuthArgs {
        AuthArgs {
            issuer: Url::parse("https://issuer.example/").expect("issuer"),
            client_id: "client".to_owned(),
            tenant_id: "tenant".to_owned(),
            redirect_uri: Url::parse("http://127.0.0.1:8765/callback").expect("redirect"),
        }
    }

    fn claims() -> IdClaims {
        IdClaims {
            iss: "https://issuer.example/".to_owned(),
            aud: Audience::One("client".to_owned()),
            exp: 2_000,
            nonce: "nonce".to_owned(),
            tenant_id: "tenant".to_owned(),
        }
    }

    #[test]
    fn claims_reject_issuer_audience_nonce_expiry_and_tenant_mismatch() {
        assert!(validate_claims(&claims(), &auth(), "nonce", 1_000).is_ok());
        let mut value = claims();
        value.iss = "https://other.example/".to_owned();
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
                .expect_err("issuer")
                .code,
            "issuer_mismatch"
        );
        let mut value = claims();
        value.aud = Audience::One("other".to_owned());
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
                .expect_err("aud")
                .code,
            "audience_mismatch"
        );
        assert_eq!(
            validate_claims(&claims(), &auth(), "wrong", 1_000)
                .expect_err("nonce")
                .code,
            "nonce_mismatch"
        );
        assert_eq!(
            validate_claims(&claims(), &auth(), "nonce", 2_000)
                .expect_err("expiry")
                .code,
            "token_expired"
        );
        let mut value = claims();
        value.tenant_id = "other".to_owned();
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
                .expect_err("tenant")
                .code,
            "tenant_mismatch"
        );
    }

    #[test]
    fn remote_plaintext_is_forbidden_but_loopback_callback_is_allowed() {
        assert!(
            secure_remote_url(&Url::parse("https://api.example/").expect("url"), false).is_ok()
        );
        assert!(secure_remote_url(&Url::parse("http://api.example/").expect("url"), true).is_err());
        assert!(
            secure_remote_url(&Url::parse("http://127.0.0.1:8000/").expect("url"), true).is_ok()
        );
    }

    #[tokio::test]
    async fn api_port_sends_exact_headers_method_path_and_canonical_body() {
        let server = MockServer::start().await;
        let device = Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678901").expect("device");
        let idempotency = Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678902").expect("key");
        let request_id = Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678903").expect("request");
        let correlation_id =
            Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678904").expect("correlation");
        let policy = RotationPolicy::try_new(vec![KeyUsage::ClientAuth], 600, Vec::new(), 3_600)
            .expect("policy");
        let prepared = prepare_policy_put(device, 4, idempotency, &policy).expect("prepared");
        Mock::given(method("PUT"))
            .and(path(format!("/api/v2/identity/devices/{device}/certificate-policy")))
            .and(header("authorization", "Bearer token-bait"))
            .and(header("x-tenant-id", "tenant-one"))
            .and(header("x-request-id", request_id.to_string()))
            .and(header("x-correlation-id", correlation_id.to_string()))
            .and(body_json(json!({"expectedGeneration":4,"idempotencyKey":idempotency,"policy":{"keyUsages":["clientAuth"],"renewBeforeSeconds":600,"validitySeconds":3600}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":{"acceptedGeneration":5,"authorizationReceiptId":"0198d5f2-70de-7a2d-b3f4-012345678905","condition":"Reconciling"}})))
            .expect(1).mount(&server).await;
        let response = send_api(
            &Url::parse(&server.uri()).expect("base"),
            &prepared,
            &TokenSet {
                access_token: "token-bait".to_owned(),
            },
            "tenant-one",
            request_id,
            correlation_id,
        )
        .await
        .expect("response");
        assert_eq!(response.0, 200);
    }

    #[tokio::test]
    async fn api_port_rejects_oversize_body_without_exposing_it() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_RESPONSE_BYTES + 1]),
            )
            .mount(&server)
            .await;
        let result = send_api(
            &Url::parse(&server.uri()).expect("base"),
            &prepare_status_get(Uuid::nil()),
            &TokenSet {
                access_token: "secret".to_owned(),
            },
            "tenant",
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .await
        .expect_err("oversize");
        assert_eq!(result.code, "response_oversize");
        assert!(!format!("{result:?}").contains("secret"));
    }
}
