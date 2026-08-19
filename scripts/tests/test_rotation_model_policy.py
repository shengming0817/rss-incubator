import json
from pathlib import Path
import subprocess
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]


class RotationModelPolicyTests(unittest.TestCase):
    def test_rotation_model_is_non_publishable_and_dependency_free(self):
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--no-deps",
            ],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
            text=True,
        )
        metadata = json.loads(result.stdout)
        packages = [
            package
            for package in metadata["packages"]
            if package["name"] == "rotation-model"
        ]

        self.assertEqual(len(packages), 1)
        package = packages[0]
        self.assertEqual(package["dependencies"], [])
        self.assertEqual(package["publish"], [])
        self.assertEqual(
            Path(package["manifest_path"]).resolve(),
            REPOSITORY / "crates/rotation-model/Cargo.toml",
        )


if __name__ == "__main__":
    unittest.main()
