def exact_keys($expected):
  type == "object" and ((keys | sort) == ($expected | sort));

exact_keys(["schemaVersion", "rssRevision", "packages"]) and
.schemaVersion == 1 and
.rssRevision == $revision and
(.packages | type == "array" and length > 0) and
([.packages[].name] | length == (unique | length)) and
all(.packages[];
  exact_keys(["name", "version", "checksum"]) and
  (.name | test("^rss-[a-z0-9]+(-[a-z0-9]+)*$")) and
  (.version | test("^[0-9A-Za-z.+-]+$")) and
  (.checksum | test("^[0-9a-f]{64}$")))
