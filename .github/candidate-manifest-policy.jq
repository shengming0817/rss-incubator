def sorted_nonempty_set:
  length > 0 and . == (sort | unique);

.schemaVersion == 2 and
.rssRevision == $revision and
(.artifactSelector |
  .workflow == "candidate-bundle.yml" and
  .artifactName == "rss-candidate-bundle-\($revision)-\(.runId)-\(.runAttempt)") and
([.packages[].name] | length == (unique | length)) and
(.profiles | length == 1) and
(.profiles[0] |
  .state == "candidate" and
  .profile == "core" and
  .assembly == "runtime" and
  (.closure |
    . as $closure |
    (.listeners | sorted_nonempty_set) and
    (.routes | sorted_nonempty_set) and
    (.providers | sorted_nonempty_set) and
    (.workers | sorted_nonempty_set) and
    (.probes | sorted_nonempty_set) and
    (.forbiddenProviders | sorted_nonempty_set) and
    all(["event-publisher", "event-subscriber", "dlx-archive-store"][];
      . as $sentinel | $closure.forbiddenProviders | index($sentinel) != null) and
    all($closure.providers[];
      . != "event-publisher" and . != "event-subscriber" and . != "dlx-archive-store")))
