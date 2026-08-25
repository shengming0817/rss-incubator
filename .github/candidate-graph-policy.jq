def coordinates:
  map({name, version, source}) | sort_by(.name, .version, .source);

def canonical_name:
  gsub("_"; "-");

def forbidden_rotation_dependency:
  (.name | canonical_name) as $name |
  ($name | startswith("rss-")) or
  ([
    "http",
    "hyper",
    "keycloak",
    "paho-mqtt",
    "reqwest",
    "rumqttc",
    "serde",
    "serde-json",
    "vault"
  ] | index($name) != null) or
  (.path != null) or
  ((.source // "") | startswith("git+"));

($bundle[0].packages |
  map({
    name,
    version,
    source: "registry+https://rss-candidate.invalid/index"
  }) |
  coordinates) as $expected |
.workspace_members as $workspace |
([.packages[] |
  select(.name as $name | $expected | any(.name == $name))] |
  coordinates) as $consumed |
([.packages[] |
  select(.name | canonical_name | startswith("rss-")) |
  select(.name as $name | $expected | any(.name == $name) | not) |
  select(.id as $id | $workspace | index($id) | not)]) as $unexpected_external |
([.packages[] |
  select(.name == "rotation-model") |
  select(.id as $id | $workspace | index($id) != null)]) as $rotation_models |
if $consumed != $expected then
  error("resolved producer package exact-set or source differs")
elif ($unexpected_external | length) != 0 then
  error("resolved graph contains an undeclared external RSS package")
elif ($rotation_models | length) != 1 then
  error("resolved workspace must contain exactly one rotation-model package")
elif $rotation_models[0].publish != [] then
  error("rotation-model must remain non-publishable")
elif ($rotation_models[0].dependencies | any(forbidden_rotation_dependency)) then
  error("rotation-model contains RSS, transport, provider, path, or Git coupling")
else
  $consumed
end
