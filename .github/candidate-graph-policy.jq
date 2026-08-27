def coordinates:
  map({name, version, source}) | sort_by(.name, .version, .source);

def canonical_name:
  gsub("_"; "-");

def dependency_closure($nodes; $root_id):
  {visited: [], frontier: [$root_id]}
  | until(
      (.frontier | length) == 0;
      .visited as $visited
      | .frontier as $frontier
      | (($visited + $frontier) | unique) as $next_visited
      | ([
          $nodes[]
          | select(.id as $id | $frontier | index($id) != null)
          | .deps[]?.pkg
          | select(. as $id | $next_visited | index($id) == null)
        ] | unique) as $next_frontier
      | {visited: $next_visited, frontier: $next_frontier}
    )
  | .visited;

def forbidden_rotation_name:
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
  ] | index($name) != null);

def forbidden_rotation_declaration:
  forbidden_rotation_name or
  (.path != null) or
  ((.source // "") | startswith("git+"));

def forbidden_rotation_package:
  forbidden_rotation_name or
  (.source == null) or
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
($rotation_models[0].dependencies // []) as $rotation_declarations |
(.resolve.nodes // []) as $resolve_nodes |
([$resolve_nodes[] |
  select(.id == $rotation_models[0].id)]) as $rotation_nodes |
(dependency_closure($resolve_nodes; $rotation_models[0].id) -
  [$rotation_models[0].id]) as $rotation_dependency_ids |
(.packages as $packages |
  [$rotation_dependency_ids[] as $dependency_id |
    $packages[] | select(.id == $dependency_id)]) as $rotation_dependencies |
if $consumed != $expected then
  error("resolved producer package exact-set or source differs")
elif ($unexpected_external | length) != 0 then
  error("resolved graph contains an undeclared external RSS package")
elif ($rotation_models | length) != 1 then
  error("resolved workspace must contain exactly one rotation-model package")
elif $rotation_models[0].publish != [] then
  error("rotation-model must remain non-publishable")
elif ($rotation_declarations | any(forbidden_rotation_declaration)) then
  error("rotation-model declares RSS, transport, provider, path, or Git coupling")
elif ($rotation_nodes | length) != 1 then
  error("resolved graph must contain exactly one rotation-model node")
elif any($rotation_dependency_ids[];
  . as $dependency_id |
  ([$resolve_nodes[] | select(.id == $dependency_id)] | length) != 1) then
  error("rotation-model dependency node lookup is incomplete")
elif ($rotation_dependencies | length) != ($rotation_dependency_ids | length) then
  error("rotation-model dependency package lookup is incomplete")
elif ($rotation_dependencies | any(forbidden_rotation_package)) then
  error("rotation-model contains RSS, transport, provider, path, or Git coupling")
else
  $consumed
end
