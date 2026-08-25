def coordinates:
  map({name, version, source}) | sort_by(.name, .version, .source);

def canonical_name:
  gsub("_"; "-");

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
if $consumed != $expected then
  error("resolved producer package exact-set or source differs")
elif ($unexpected_external | length) != 0 then
  error("resolved graph contains an undeclared external RSS package")
else
  $consumed
end
