import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "candidate-proof.py"
SPEC = importlib.util.spec_from_file_location("candidate_proof", SCRIPT)
candidate_proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate_proof)

REVISION = "0123456789abcdef0123456789abcdef01234567"


def index_path(name: str) -> Path:
    if len(name) == 1:
        return Path("1") / name
    if len(name) == 2:
        return Path("2") / name
    if len(name) == 3:
        return Path("3") / name[0] / name
    return Path(name[:2]) / name[2:4] / name


def crate_bytes(
    name: str,
    version: str,
    revision: str = REVISION,
    unsafe=False,
    dirty="missing",
) -> bytes:
    output = io.BytesIO()
    root = f"{name}-{version}"
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        git = {"sha1": revision}
        if dirty != "missing":
            git["dirty"] = dirty
        files = {
            f"{root}/Cargo.toml": (
                f'[package]\nname = "{name}"\nversion = "{version}"\n'
            ).encode(),
            f"{root}/.cargo_vcs_info.json": json.dumps({"git": git}).encode(),
        }
        for path, contents in files.items():
            entry = tarfile.TarInfo(path)
            entry.size = len(contents)
            archive.addfile(entry, io.BytesIO(contents))
        if unsafe:
            link = tarfile.TarInfo(f"{root}/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            archive.addfile(link)
    return output.getvalue()


def write_bundle(root: Path, names=("rss-diag-context", "rss-trace-context", "rss-third")):
    packages = []
    for name in names:
        version = "0.1.0"
        archive = crate_bytes(name, version)
        checksum = hashlib.sha256(archive).hexdigest()
        packages.append({"name": name, "version": version, "checksum": checksum})
        archive_path = root / "registry/crates" / name / version / "download"
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(archive)
        record_path = root / "registry/index" / index_path(name)
        record_path.parent.mkdir(parents=True, exist_ok=True)
        record_path.write_text(
            json.dumps(
                {
                    "name": name,
                    "vers": version,
                    "deps": [],
                    "cksum": checksum,
                    "features": {},
                    "yanked": False,
                    "links": None,
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
    packages.sort(key=lambda package: package["name"])
    (root / "candidate-bundle.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "rssRevision": REVISION,
                "packages": packages,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return packages


class CandidateBundleTests(unittest.TestCase):
    def test_conformance_candidate_is_mandatory(self):
        package = candidate_proof.CandidatePackage(
            "rss-diag-context", "0.1.0", "aa" * 32, Path("unused")
        )
        bundle = candidate_proof.CandidateBundle(Path("unused"), REVISION, (package,))
        with self.assertRaises(candidate_proof.ProofError):
            candidate_proof.require_conformance_candidate(bundle)

    def test_candidate_fixture_template_is_closed_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixtures/rss-conformance-consumer"
            fixture.mkdir(parents=True)
            (fixture / "Cargo.toml.in").write_text("[package]\nname='wrong'\n", encoding="utf-8")
            with self.assertRaises(candidate_proof.ProofError):
                candidate_proof.validate_conformance_fixture(root)

    def test_valid_bundle_is_generic_and_sorted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            bundle = candidate_proof.validate_bundle(root)
            self.assertEqual(
                [package.name for package in bundle.packages],
                ["rss-diag-context", "rss-third", "rss-trace-context"],
            )

    def test_unknown_manifest_field_and_missing_candidate_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            manifest_path = root / "candidate-bundle.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["unknown"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(candidate_proof.ProofError):
                candidate_proof.validate_bundle(root)

            del manifest["unknown"]
            manifest["packages"].pop()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(candidate_proof.ProofError):
                candidate_proof.validate_bundle(root)

    def test_unknown_index_field_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, names=("rss-diag-context",))
            record_path = root / "registry/index/rs/s-/rss-diag-context"
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["unknown"] = True
            record_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaises(candidate_proof.ProofError):
                candidate_proof.validate_bundle(root)

    def test_checksum_vcs_and_unsafe_archive_fail_closed(self):
        for mutation in ("checksum", "vcs", "unsafe"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                packages = write_bundle(root, names=("rss-diag-context",))
                archive_path = root / "registry/crates/rss-diag-context/0.1.0/download"
                if mutation == "checksum":
                    packages[0]["checksum"] = "00" * 32
                    manifest = json.loads(
                        (root / "candidate-bundle.json").read_text(encoding="utf-8")
                    )
                    manifest["packages"] = packages
                    (root / "candidate-bundle.json").write_text(
                        json.dumps(manifest), encoding="utf-8"
                    )
                else:
                    archive = crate_bytes(
                        "rss-diag-context",
                        "0.1.0",
                        revision="f" * 40 if mutation == "vcs" else REVISION,
                        unsafe=mutation == "unsafe",
                    )
                    archive_path.write_bytes(archive)
                    checksum = hashlib.sha256(archive).hexdigest()
                    manifest = json.loads(
                        (root / "candidate-bundle.json").read_text(encoding="utf-8")
                    )
                    manifest["packages"][0]["checksum"] = checksum
                    (root / "candidate-bundle.json").write_text(
                        json.dumps(manifest), encoding="utf-8"
                    )
                    record = json.loads(
                        (root / "registry/index/rs/s-/rss-diag-context").read_text(
                            encoding="utf-8"
                        )
                    )
                    record["cksum"] = checksum
                    (root / "registry/index/rs/s-/rss-diag-context").write_text(
                        json.dumps(record) + "\n", encoding="utf-8"
                    )
                with self.assertRaises(candidate_proof.ProofError):
                    candidate_proof.validate_bundle(root)

    def test_archive_dirty_marker_is_typed_and_fail_closed(self):
        for dirty in (None, "false", 0, 1, True):
            with self.subTest(dirty=dirty), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = crate_bytes("rss-diag-context", "0.1.0", dirty=dirty)
                checksum = hashlib.sha256(archive).hexdigest()
                archive_path = root / "registry/crates/rss-diag-context/0.1.0/download"
                archive_path.parent.mkdir(parents=True)
                archive_path.write_bytes(archive)
                record_path = root / "registry/index/rs/s-/rss-diag-context"
                record_path.parent.mkdir(parents=True)
                record_path.write_text(
                    json.dumps(
                        {
                            "name": "rss-diag-context",
                            "vers": "0.1.0",
                            "deps": [],
                            "cksum": checksum,
                            "features": {},
                            "yanked": False,
                            "links": None,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                (root / "candidate-bundle.json").write_text(
                    json.dumps(
                        {
                            "schemaVersion": 1,
                            "rssRevision": REVISION,
                            "packages": [
                                {
                                    "name": "rss-diag-context",
                                    "version": "0.1.0",
                                    "checksum": checksum,
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                with self.assertRaises(candidate_proof.ProofError):
                    candidate_proof.validate_bundle(root)

    def test_path_or_internal_rss_dependencies_fail_closed(self):
        base = {
            "name": "rss-diag-context",
            "req": "=0.1.0",
            "kind": None,
            "rename": "rss_diag_context",
            "optional": False,
            "uses_default_features": True,
            "features": [],
            "target": None,
            "registry": None,
        }
        bundle_names = {"rss-diag-context"}
        for source, name in [
            (None, "rss-diag-context"),
            ("git+https://invalid", "rss-diag-context"),
            ("registry+https://github.com/rust-lang/crates.io-index", "rss-internal"),
        ]:
            dependency = dict(base, source=source, name=name)
            metadata = {
                "packages": [
                    {
                        "name": "consumer",
                        "manifest_path": "/tmp/Cargo.toml",
                        "dependencies": [dependency],
                    }
                ]
            }
            with self.assertRaises(candidate_proof.ProofError):
                candidate_proof.direct_rss_dependencies(metadata, bundle_names)

    def test_manifest_rejects_workspace_inheritance_and_underscore_internal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "Cargo.toml"
            manifest.write_text(
                '[package]\nname = "consumer"\nversion = "0.0.0"\n'
                '[dependencies]\nrss_diag_context = { workspace = true }\n',
                encoding="utf-8",
            )
            metadata = {
                "workspace_members": ["consumer-id"],
                "packages": [
                    {
                        "id": "consumer-id",
                        "name": "consumer",
                        "manifest_path": str(manifest),
                    }
                ],
            }
            with self.assertRaises(candidate_proof.ProofError):
                candidate_proof.validate_manifest_dependency_sources(
                    metadata, {"rss-diag-context"}
                )

    def test_rewrite_must_preserve_dependency_semantics(self):
        package = candidate_proof.CandidatePackage(
            "rss-diag-context", "0.1.0", "aa" * 32, Path("unused")
        )
        workspace = {"name": "consumer"}
        baseline = {
            "name": package.name,
            "req": "^0.1",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "kind": "dev",
            "rename": "diagnostics",
            "optional": True,
            "uses_default_features": False,
            "features": ["std"],
            "target": "cfg(unix)",
        }
        rewritten = dict(
            baseline,
            req="=0.1.0",
            source="registry+file:///candidate/index",
            optional=False,
        )
        metadata = {"packages": [dict(workspace, dependencies=[rewritten])]}
        bundle = candidate_proof.CandidateBundle(
            Path("unused"), REVISION, (package,)
        )
        with self.assertRaises(candidate_proof.ProofError):
            candidate_proof.validate_rewritten_dependencies(
                [(workspace, baseline)],
                metadata,
                bundle,
                "registry+file:///candidate/index",
            )

    def test_resolution_rejects_git_or_checksum_drift(self):
        candidate = candidate_proof.CandidatePackage(
            "rss-diag-context", "0.1.0", "aa" * 32, Path("unused")
        )
        bundle = candidate_proof.CandidateBundle(
            Path("unused"), REVISION, (candidate,)
        )
        source = "registry+file:///candidate/index"
        workspace_id = "path+file:///consumer#0.0.0"
        metadata = {
            "workspace_members": [workspace_id],
            "packages": [
                {
                    "id": workspace_id,
                    "name": "rss-consumer-smoke",
                    "source": None,
                    "checksum": None,
                },
                {
                    "id": "rss-diag-context@0.1.0",
                    "name": candidate.name,
                    "version": candidate.version,
                    "source": source,
                    "checksum": candidate.checksum,
                },
                {
                    "id": "bad@1.0.0",
                    "name": "bad",
                    "version": "1.0.0",
                    "source": "git+https://invalid",
                    "checksum": None,
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            with self.assertRaises(candidate_proof.ProofError):
                candidate_proof.validate_resolution(repository, bundle, metadata, source)

    def test_invalid_cli_does_not_change_checkout_status(self):
        repository = SCRIPT.parents[1]
        before = subprocess.run(
            ["/usr/bin/git", "status", "--porcelain=v2", "-z", "--untracked-files=all"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["python3", str(SCRIPT), "--bundle", str(Path(directory).resolve())],
                cwd=repository,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        unknown = subprocess.run(
            ["python3", str(SCRIPT), "--unknown"],
            cwd=repository,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(unknown.returncode, 0)
        after = subprocess.run(
            ["/usr/bin/git", "status", "--porcelain=v2", "-z", "--untracked-files=all"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(before, after)

    def test_execute_reaches_locked_offline_matrix_and_fails_closed(self):
        package = candidate_proof.CandidatePackage(
            "rss-conformance", "0.1.0", "aa" * 32, Path("unused")
        )
        bundle = candidate_proof.CandidateBundle(
            Path("/synthetic-bundle"), REVISION, (package,)
        )
        baseline_dependency = {
            "name": package.name,
            "req": "=0.1.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "kind": None,
            "rename": "rss_conformance",
            "optional": False,
            "uses_default_features": True,
            "features": [],
            "target": None,
        }

        def run_once(fail_test):
            commands = []
            snapshots = []

            def materialize(_repository, destination):
                destination.mkdir(parents=True)
                snapshots.append(destination)

            def copytree(_source, destination):
                (destination / "index").mkdir(parents=True)
                (destination / "crates").mkdir()

            def visible(args, cwd, _env, _label):
                commands.append((tuple(args), cwd))
                if args[:2] == ["cargo", "generate-lockfile"]:
                    (cwd / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
                if fail_test and args[:2] == ["cargo", "test"]:
                    raise candidate_proof.ProofError("synthetic test failure")

            metadata_calls = 0

            def metadata(repository, _env, *, offline, no_deps):
                nonlocal metadata_calls
                metadata_calls += 1
                workspace = {
                    "id": "consumer-id",
                    "name": "consumer",
                    "manifest_path": str(repository / "Cargo.toml"),
                }
                if metadata_calls == 1:
                    (repository / "Cargo.toml").write_text(
                        '[package]\nname = "consumer"\nversion = "0.0.0"\n'
                        '[dependencies]\nrss_conformance = '
                        '{ package = "rss-conformance", version = "=0.1.0" }\n',
                        encoding="utf-8",
                    )
                    return {
                        "workspace_members": ["consumer-id"],
                        "packages": [dict(workspace, dependencies=[baseline_dependency])],
                    }
                self.assertTrue(offline)
                self.assertTrue(no_deps if metadata_calls == 2 else not no_deps)
                config = tomllib.loads(
                    (repository / ".cargo/config.toml").read_text(encoding="utf-8")
                )
                source = "registry+" + config["registries"]["rss-candidate"]["index"]
                rewritten = dict(baseline_dependency, source=source)
                return {
                    "workspace_members": ["consumer-id"],
                    "packages": [dict(workspace, dependencies=[rewritten])],
                }

            patches = (
                mock.patch.object(candidate_proof, "validate_bundle", return_value=bundle),
                mock.patch.object(candidate_proof, "materialize_head", side_effect=materialize),
                mock.patch.object(candidate_proof.shutil, "copytree", side_effect=copytree),
                mock.patch.object(candidate_proof, "initialize_registry"),
                mock.patch.object(candidate_proof, "command_env", return_value={}),
                mock.patch.object(candidate_proof, "run_visible", side_effect=visible),
                mock.patch.object(candidate_proof, "cargo_metadata", side_effect=metadata),
                mock.patch.object(candidate_proof, "validate_resolution", return_value=[package.name]),
                mock.patch.object(candidate_proof, "run_capture", return_value=("b" * 40).encode()),
                mock.patch.object(candidate_proof, "materialize_conformance_fixture"),
                mock.patch.object(candidate_proof, "validate_conformance_fixture_dependency"),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10]:
                if fail_test:
                    with self.assertRaises(candidate_proof.ProofError):
                        candidate_proof.execute(Path("/real-checkout"), bundle.root)
                    return commands, snapshots
                summary = candidate_proof.execute(Path("/real-checkout"), bundle.root)
                self.assertEqual(summary["consumedPackages"], [package.name])
                return commands, snapshots

        commands, snapshots = run_once(fail_test=False)
        matrix = {args[1]: args for args, _cwd in commands if len(args) > 1}
        for command in ("check", "test", "clippy"):
            self.assertIn(command, matrix)
            self.assertIn("--locked", matrix[command])
            self.assertIn("--offline", matrix[command])
        self.assertEqual(matrix["generate-lockfile"], ("cargo", "generate-lockfile"))
        self.assertTrue(snapshots)
        self.assertTrue(snapshots[0].parent.name.startswith("rss-incubator-candidate-"))
        self.assertTrue(all(cwd == snapshots[0] for _args, cwd in commands))
        command_args = [args for args, _cwd in commands]
        generated = command_args.index(("cargo", "generate-lockfile"))
        self.assertEqual(command_args[generated + 1], ("cargo", "fetch", "--locked"))
        first_matrix = min(
            command_args.index(matrix[subcommand])
            for subcommand in ("check", "test", "clippy")
        )
        self.assertLess(generated + 1, first_matrix)
        failed_commands, _ = run_once(fail_test=True)
        self.assertTrue(any(args[:2] == ("cargo", "test") for args, _ in failed_commands))

    def test_candidate_metadata_command_is_locked_and_offline(self):
        with mock.patch.object(candidate_proof, "run_capture", return_value=b"{}") as capture:
            candidate_proof.cargo_metadata(
                Path("/snapshot"), {}, offline=True, no_deps=False
            )
        args = capture.call_args.args[0]
        self.assertEqual(args[:2], ["cargo", "metadata"])
        self.assertIn("--locked", args)
        self.assertIn("--offline", args)


if __name__ == "__main__":
    unittest.main()
