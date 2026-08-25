import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class CandidateWorkflowSecurityTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def test_pull_requests_use_base_controlled_workflow(self):
        self.assertIn("  pull_request_target:\n", self.workflow)
        self.assertNotIn("  pull_request:\n", self.workflow)

    def test_cross_repository_secret_is_confined_to_artifact_job(self):
        artifact_job = self.workflow.split("  candidate-artifact:\n", 1)[1].split(
            "  candidate-consumption:\n", 1
        )[0]
        consumer_job = self.workflow.split("  candidate-consumption:\n", 1)[1]
        self.assertEqual(2, artifact_job.count("RSS_ARTIFACTS_READ_TOKEN"))
        self.assertNotIn("RSS_ARTIFACTS_READ_TOKEN", consumer_job)
        self.assertNotIn("actions/checkout", artifact_job)

    def test_manifest_policy_and_local_transport_are_shared_carriers(self):
        self.assertIn("candidate-manifest-policy.jq", self.workflow)
        self.assertIn("scripts/prepare-candidate-transport.sh", self.workflow)
        self.assertIn("scripts/verify-core-candidate-migration-image.sh", self.workflow)
        self.assertIn(
            "scripts/prepare-candidate-transport.sh",
            (ROOT / "README.md").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
