#!/usr/bin/env python3
"""Prove an immutable RSS candidate bundle from an isolated incubator snapshot."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from typing import NamedTuple


RSS_NAME = re.compile(r"rss-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
LOWER_HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
CONFORMANCE_PACKAGE = "rss-conformance"
CONFORMANCE_FIXTURE = Path("fixtures/rss-conformance-consumer")
MATERIALIZED_FIXTURE = Path("crates/rss-conformance-candidate-fixture")
CONFORMANCE_VERSION_TOKEN = "__RSS_CONFORMANCE_VERSION__"


class ProofError(RuntimeError):
    pass


class CandidatePackage(NamedTuple):
    name: str
    version: str
    checksum: str
    archive: Path


class CandidateBundle(NamedTuple):
    root: Path
    rss_revision: str
    packages: tuple[CandidatePackage, ...]


def require_conformance_candidate(bundle: CandidateBundle) -> CandidatePackage:
    matches = [package for package in bundle.packages if package.name == CONFORMANCE_PACKAGE]
    if len(matches) != 1:
        raise ProofError("candidate bundle must contain exactly one `rss-conformance` package")
    return matches[0]


def validate_conformance_fixture(repository: Path):
    fixture = repository / CONFORMANCE_FIXTURE
    expected = {Path("Cargo.toml.in"), Path("src/lib.rs")}
    if regular_files(fixture) != expected:
        raise ProofError("rss-conformance candidate fixture exact-set differs")
    template = (fixture / "Cargo.toml.in").read_text(encoding="utf-8")
    if template.count(CONFORMANCE_VERSION_TOKEN) != 1:
        raise ProofError("rss-conformance fixture must contain one exact version token")
    rendered = template.replace(CONFORMANCE_VERSION_TOKEN, "0.1.0")
    try:
        manifest = tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as error:
        raise ProofError("rss-conformance fixture manifest template is invalid") from error
    require_keys(manifest, {"package", "dependencies", "dev-dependencies", "lints"}, "conformance fixture")
    package = manifest["package"]
    require_keys(package, {"name", "version", "edition", "publish"}, "conformance fixture package")
    if package != {
        "name": "rss-conformance-candidate-fixture",
        "version": "0.0.0",
        "edition": "2024",
        "publish": False,
    }:
        raise ProofError("rss-conformance fixture package identity differs")
    dependency = manifest["dependencies"].get(CONFORMANCE_PACKAGE)
    if dependency != {"version": "=0.1.0", "registry": "rss-candidate"}:
        raise ProofError("rss-conformance fixture dependency must be exact and registry-only")
    if manifest["dev-dependencies"] != {"tokio": {"version": "1", "features": ["macros", "rt"]}}:
        raise ProofError("rss-conformance fixture dev dependency exact-set differs")
    if manifest["lints"] != {"workspace": True}:
        raise ProofError("rss-conformance fixture must inherit workspace lints")


def materialize_conformance_fixture(snapshot: Path, candidate: CandidatePackage):
    validate_conformance_fixture(snapshot)
    source = snapshot / CONFORMANCE_FIXTURE
    destination = snapshot / MATERIALIZED_FIXTURE
    destination.mkdir(parents=True)
    shutil.copy2(source / "src/lib.rs", destination / "src/lib.rs")
    template = (source / "Cargo.toml.in").read_text(encoding="utf-8")
    (destination / "Cargo.toml").write_text(
        template.replace(CONFORMANCE_VERSION_TOKEN, candidate.version), encoding="utf-8"
    )


def strict_object(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ProofError(f"duplicate JSON field `{key}`")
        output[key] = value
    return output


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProofError(f"invalid JSON `{path}`: {error}") from error


def require_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise ProofError(f"{label} fields differ: expected={sorted(expected)} actual={actual}")


def index_relative_path(name: str) -> Path:
    if len(name) == 1:
        return Path("1") / name
    if len(name) == 2:
        return Path("2") / name
    if len(name) == 3:
        return Path("3") / name[0] / name
    return Path(name[:2]) / name[2:4] / name


def regular_files(root: Path) -> set[Path]:
    if not root.is_dir() or root.is_symlink():
        raise ProofError(f"bundle directory is missing or unsafe: {root}")
    output = set()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            path = current_path / directory
            if path.is_symlink():
                raise ProofError(f"bundle contains a symlink directory: {path}")
        for filename in files:
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                raise ProofError(f"bundle contains a non-regular file: {path}")
            output.add(path.relative_to(root))
    return output


def validate_archive(package: CandidatePackage, rss_revision: str):
    payload = package.archive.read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != package.checksum:
        raise ProofError(f"archive checksum differs for `{package.name}@{package.version}`")
    expected_root = f"{package.name}-{package.version}"
    cargo_name = f"{expected_root}/Cargo.toml"
    vcs_name = f"{expected_root}/.cargo_vcs_info.json"
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or path.parts[0] != expected_root
                    or not (member.isfile() or member.isdir())
                ):
                    raise ProofError(f"archive contains an unsafe entry: {member.name}")
            names = [member.name for member in members if member.isfile()]
            if names.count(cargo_name) != 1 or names.count(vcs_name) != 1:
                raise ProofError(f"archive identity files are incomplete for `{package.name}`")
            cargo_file = archive.extractfile(cargo_name)
            vcs_file = archive.extractfile(vcs_name)
            if cargo_file is None or vcs_file is None:
                raise ProofError(f"archive identity files cannot be read for `{package.name}`")
            cargo = tomllib.loads(cargo_file.read().decode("utf-8"))
            vcs = json.loads(vcs_file.read().decode("utf-8"), object_pairs_hook=strict_object)
    except (tarfile.TarError, OSError, UnicodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        raise ProofError(f"invalid crate archive `{package.name}`: {error}") from error
    if cargo.get("package", {}).get("name") != package.name:
        raise ProofError(f"archive package name differs for `{package.name}`")
    if cargo.get("package", {}).get("version") != package.version:
        raise ProofError(f"archive package version differs for `{package.name}`")
    git = vcs.get("git") if isinstance(vcs, dict) else None
    dirty = git.get("dirty", False) if isinstance(git, dict) else None
    if (
        not isinstance(git, dict)
        or git.get("sha1") != rss_revision
        or dirty is not False
    ):
        raise ProofError(f"archive VCS revision differs for `{package.name}`")


def validate_bundle(bundle_root: Path) -> CandidateBundle:
    if not bundle_root.is_absolute():
        raise ProofError("candidate bundle path must be absolute")
    if not bundle_root.is_dir() or bundle_root.is_symlink():
        raise ProofError("candidate bundle path must be a real directory")
    manifest_path = bundle_root / "candidate-bundle.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ProofError("candidate bundle manifest is missing or unsafe")
    manifest = read_json(manifest_path)
    require_keys(manifest, {"schemaVersion", "rssRevision", "packages"}, "bundle manifest")
    if manifest["schemaVersion"] != 1:
        raise ProofError("candidate bundle schemaVersion must be exactly 1")
    revision = manifest["rssRevision"]
    if not isinstance(revision, str) or LOWER_HEX_40.fullmatch(revision) is None:
        raise ProofError("candidate bundle rssRevision must be lowercase 40-hex")
    raw_packages = manifest["packages"]
    if not isinstance(raw_packages, list) or not raw_packages:
        raise ProofError("candidate bundle packages must be a non-empty array")
    packages = []
    seen = set()
    for index, raw in enumerate(raw_packages):
        require_keys(raw, {"name", "version", "checksum"}, f"bundle package[{index}]")
        name, version, checksum = raw["name"], raw["version"], raw["checksum"]
        if not isinstance(name, str) or RSS_NAME.fullmatch(name) is None:
            raise ProofError(f"invalid candidate package name: {name!r}")
        if name in seen:
            raise ProofError(f"duplicate candidate package `{name}`")
        seen.add(name)
        if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
            raise ProofError(f"invalid exact candidate version for `{name}`")
        if not isinstance(checksum, str) or LOWER_HEX_64.fullmatch(checksum) is None:
            raise ProofError(f"invalid candidate checksum for `{name}`")
        archive = bundle_root / "registry/crates" / name / version / "download"
        packages.append(CandidatePackage(name, version, checksum, archive))
    if [package.name for package in packages] != sorted(seen):
        raise ProofError("candidate bundle packages must be sorted by name")

    index_root = bundle_root / "registry/index"
    crates_root = bundle_root / "registry/crates"
    expected_index = {index_relative_path(package.name) for package in packages}
    expected_archives = {
        Path(package.name) / package.version / "download" for package in packages
    }
    if regular_files(index_root) != expected_index:
        raise ProofError("candidate registry index exact-set differs from manifest")
    if regular_files(crates_root) != expected_archives:
        raise ProofError("candidate registry archive exact-set differs from manifest")

    for package in packages:
        record_path = index_root / index_relative_path(package.name)
        lines = record_path.read_text(encoding="utf-8").splitlines()
        if len(lines) != 1 or not lines[0]:
            raise ProofError(f"candidate index must contain one record for `{package.name}`")
        try:
            record = json.loads(lines[0], object_pairs_hook=strict_object)
        except json.JSONDecodeError as error:
            raise ProofError(f"invalid candidate index for `{package.name}`") from error
        require_keys(
            record,
            {"name", "vers", "deps", "cksum", "features", "yanked", "links"},
            f"candidate index `{package.name}`",
        )
        if (
            not isinstance(record, dict)
            or record.get("name") != package.name
            or record.get("vers") != package.version
            or record.get("cksum") != package.checksum
            or record.get("yanked") is not False
        ):
            raise ProofError(f"candidate index identity differs for `{package.name}`")
        validate_archive(package, revision)
    return CandidateBundle(bundle_root, revision, tuple(packages))


def is_rss_package_name(name):
    return isinstance(name, str) and (name.startswith("rss-") or name.startswith("rss_"))


def canonical_package_name(name: str) -> str:
    return name.replace("_", "-")


def manifest_dependency_tables(manifest):
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(key, {})
        if isinstance(table, dict):
            yield table
    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(key, {})
                if isinstance(table, dict):
                    yield table


def validate_manifest_dependency_sources(metadata, bundle_names: set[str]):
    workspace_ids = set(metadata.get("workspace_members", []))
    found = set()
    for package in metadata.get("packages", []):
        if package.get("id") not in workspace_ids:
            continue
        manifest_path = Path(package["manifest_path"])
        try:
            manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ProofError(f"cannot inspect workspace manifest `{manifest_path}`: {error}") from error
        for table in manifest_dependency_tables(manifest):
            for alias, specification in table.items():
                declared_name = (
                    specification.get("package", alias)
                    if isinstance(specification, dict)
                    else alias
                )
                if not is_rss_package_name(declared_name):
                    continue
                canonical = canonical_package_name(declared_name)
                if canonical not in bundle_names:
                    raise ProofError(f"RSS dependency `{declared_name}` is outside the Release Surface bundle")
                if isinstance(specification, dict) and any(
                    key in specification for key in ("path", "git", "workspace")
                ):
                    raise ProofError(f"RSS dependency `{declared_name}` must be declared from a registry")
                found.add(canonical)
    if not found:
        raise ProofError("workspace manifests declare no RSS candidate consumers")
    return found


def direct_rss_dependencies(metadata, bundle_names: set[str]):
    dependencies = []
    for package in metadata.get("packages", []):
        for dependency in package.get("dependencies", []):
            name = dependency.get("name")
            if not is_rss_package_name(name):
                continue
            canonical = canonical_package_name(name)
            source = dependency.get("source")
            if canonical not in bundle_names:
                raise ProofError(f"RSS dependency `{name}` is outside the Release Surface bundle")
            if not isinstance(source, str) or not source.startswith("registry+"):
                raise ProofError(f"RSS dependency `{name}` must use a registry source")
            dependencies.append((package, dependency))
    if not dependencies:
        raise ProofError("workspace has no direct RSS candidate consumers")
    return dependencies


def dependency_identity(workspace_package, dependency):
    return (
        workspace_package["name"],
        dependency["name"],
        dependency.get("rename"),
        dependency.get("kind"),
        dependency.get("target"),
    )


def dependency_semantics(dependency):
    return (
        bool(dependency.get("optional")),
        bool(dependency.get("uses_default_features", True)),
        tuple(sorted(dependency.get("features", []))),
    )


def validate_rewritten_dependencies(baseline_dependencies, metadata, bundle, expected_source):
    candidates = {package.name: package for package in bundle.packages}
    rewritten = direct_rss_dependencies(metadata, set(candidates))
    baseline = {
        dependency_identity(workspace_package, dependency): dependency_semantics(dependency)
        for workspace_package, dependency in baseline_dependencies
    }
    actual = {}
    for workspace_package, dependency in rewritten:
        if workspace_package["name"] == "rss-conformance-candidate-fixture":
            continue
        identity = dependency_identity(workspace_package, dependency)
        candidate = candidates[canonical_package_name(dependency["name"])]
        if dependency.get("source") != expected_source:
            raise ProofError(f"rewritten RSS dependency `{dependency['name']}` has the wrong source")
        if dependency.get("req") != f"={candidate.version}":
            raise ProofError(f"rewritten RSS dependency `{dependency['name']}` is not exact")
        if identity in actual:
            raise ProofError(f"rewritten RSS dependency identity is duplicated: {identity}")
        actual[identity] = dependency_semantics(dependency)
    if actual != baseline:
        raise ProofError("rewritten RSS dependency kinds, targets, features, or aliases differ")


def validate_conformance_fixture_dependency(metadata, bundle, candidate, expected_source):
    matches = [
        (workspace_package, dependency)
        for workspace_package, dependency in direct_rss_dependencies(
            metadata, {package.name for package in bundle.packages}
        )
        if workspace_package["name"] == "rss-conformance-candidate-fixture"
        and canonical_package_name(dependency["name"]) == candidate.name
    ]
    if len(matches) != 1:
        raise ProofError("materialized fixture must consume rss-conformance exactly once")
    _workspace, dependency = matches[0]
    if (
        dependency.get("source") != expected_source
        or dependency.get("req") != f"={candidate.version}"
        or dependency.get("kind") is not None
        or dependency.get("optional")
        or dependency.get("features")
    ):
        raise ProofError("materialized fixture dependency identity/source differs")


def command_env(temp_root: Path):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("CARGO_") and key not in {"RUSTC_WRAPPER", "RUSTDOCFLAGS", "RUSTFLAGS"}
    }
    env.update(
        {
            "CARGO_HOME": str(temp_root / "cargo-home"),
            "CARGO_TARGET_DIR": str(temp_root / "target"),
            "CARGO_TERM_COLOR": "always",
            "CARGO_INCREMENTAL": "0",
        }
    )
    return env


def run_capture(args, cwd: Path, env, label: str) -> bytes:
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ProofError(f"{label} failed: {detail}")
    return result.stdout


def run_visible(args, cwd: Path, env, label: str):
    result = subprocess.run(args, cwd=cwd, env=env)
    if result.returncode != 0:
        raise ProofError(f"{label} failed with exit code {result.returncode}")


def git_status(repository: Path) -> bytes:
    return run_capture(
        ["/usr/bin/git", "status", "--porcelain=v2", "-z", "--untracked-files=all"],
        repository,
        os.environ.copy(),
        "read incubator status",
    )


def materialize_head(repository: Path, destination: Path):
    archive_path = destination.parent / "incubator-head.tar"
    run_capture(
        ["/usr/bin/git", "archive", "--format=tar", "-o", str(archive_path), "HEAD"],
        repository,
        os.environ.copy(),
        "materialize committed incubator HEAD",
    )
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ProofError(f"incubator archive contains an unsafe entry: {member.name}")
        archive.extractall(destination, filter="data")


def initialize_registry(registry: Path):
    index = registry / "index"
    crates = registry / "crates"
    (index / "config.json").write_text(
        json.dumps(
            {"dl": f"{crates.resolve().as_uri()}/{{crate}}/{{version}}/download"},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "RSS candidate proof",
            "GIT_AUTHOR_EMAIL": "candidate-proof@invalid",
            "GIT_COMMITTER_NAME": "RSS candidate proof",
            "GIT_COMMITTER_EMAIL": "candidate-proof@invalid",
        }
    )
    for args in (["/usr/bin/git", "init", "-q"], ["/usr/bin/git", "add", "."], ["/usr/bin/git", "commit", "-qm", "candidate registry"]):
        run_capture(args, index, env, "initialize candidate registry")


def cargo_metadata(repository: Path, env, *, offline: bool, no_deps: bool):
    args = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if offline:
        args.append("--offline")
    if no_deps:
        args.append("--no-deps")
    return json.loads(run_capture(args, repository, env, "load Cargo metadata"))


def rewrite_dependencies(repository: Path, dependencies, packages, env):
    by_name = {package.name: package for package in packages}
    for workspace_package, dependency in dependencies:
        candidate = by_name[canonical_package_name(dependency["name"])]
        args = [
            "cargo",
            "add",
            f"{candidate.name}@={candidate.version}",
            "--registry",
            "rss-candidate",
            "--package",
            workspace_package["name"],
        ]
        if dependency.get("rename"):
            args.extend(["--rename", dependency["rename"]])
        if dependency.get("kind") == "dev":
            args.append("--dev")
        elif dependency.get("kind") == "build":
            args.append("--build")
        if dependency.get("target"):
            args.extend(["--target", dependency["target"]])
        if dependency.get("optional"):
            args.append("--optional")
        if not dependency.get("uses_default_features", True):
            args.append("--no-default-features")
        if dependency.get("features"):
            args.extend(["--features", ",".join(dependency["features"])])
        run_visible(args, repository, env, f"select `{candidate.name}` candidate")


def prepare_candidate_lock(repository: Path, env):
    run_visible(
        ["cargo", "generate-lockfile"],
        repository,
        env,
        "generate candidate lock",
    )
    run_visible(
        ["cargo", "fetch", "--locked"],
        repository,
        env,
        "prefetch candidate lock",
    )


def validate_resolution(repository: Path, bundle: CandidateBundle, metadata, expected_source: str):
    bundle_by_name = {package.name: package for package in bundle.packages}
    workspace_ids = set(metadata.get("workspace_members", []))
    consumed = set()
    for package in metadata.get("packages", []):
        if package.get("id") in workspace_ids:
            continue
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("registry+"):
            raise ProofError(f"resolved package `{package.get('name')}` is not registry-only")
        if not is_rss_package_name(package.get("name")):
            continue
        name = package["name"]
        canonical = canonical_package_name(name)
        candidate = bundle_by_name.get(canonical)
        if candidate is None:
            raise ProofError(f"resolved RSS package `{name}` is outside candidate bundle")
        if (
            package.get("version") != candidate.version
            or source != expected_source
        ):
            raise ProofError(f"resolved RSS identity/source differs for `{name}`")
        consumed.add(canonical)
    if not consumed:
        raise ProofError("candidate resolution did not execute an RSS package")

    lock = tomllib.loads((repository / "Cargo.lock").read_text(encoding="utf-8"))
    workspace_names = {
        package["name"]
        for package in metadata.get("packages", [])
        if package.get("id") in workspace_ids
    }
    seen = set()
    for package in lock.get("package", []):
        name = package.get("name")
        if name in workspace_names and package.get("source") is None:
            continue
        source = package.get("source")
        checksum = package.get("checksum")
        if not isinstance(source, str) or not source.startswith("registry+"):
            raise ProofError(f"lock package `{name}` is not registry-only")
        if not isinstance(checksum, str) or LOWER_HEX_64.fullmatch(checksum) is None:
            raise ProofError(f"lock package `{name}` has no registry checksum")
        if not is_rss_package_name(name):
            continue
        canonical = canonical_package_name(name)
        if canonical not in consumed:
            raise ProofError(f"candidate lock contains unexpected RSS package `{name}`")
        candidate = bundle_by_name[canonical]
        if (
            package.get("version") != candidate.version
            or source != expected_source
            or checksum != candidate.checksum
        ):
            raise ProofError(f"candidate lock identity/checksum differs for `{name}`")
        if canonical in seen:
            raise ProofError(f"candidate lock contains duplicate package `{name}`")
        seen.add(canonical)
    if seen != consumed:
        raise ProofError("candidate lock/resolved RSS exact-set differs")
    return sorted(consumed)


def execute(repository: Path, bundle_root: Path):
    bundle = validate_bundle(bundle_root)
    candidate = require_conformance_candidate(bundle)
    with tempfile.TemporaryDirectory(prefix="rss-incubator-candidate-") as directory:
        temp_root = Path(directory)
        snapshot = temp_root / "repository"
        materialize_head(repository, snapshot)
        registry = temp_root / "registry"
        shutil.copytree(bundle.root / "registry", registry)
        initialize_registry(registry)
        env = command_env(temp_root)

        run_visible(["cargo", "fetch", "--locked"], snapshot, env, "prefetch committed lock")
        baseline = cargo_metadata(snapshot, env, offline=False, no_deps=True)
        validate_manifest_dependency_sources(
            baseline, {package.name for package in bundle.packages}
        )
        dependencies = direct_rss_dependencies(
            baseline, {package.name for package in bundle.packages}
        )
        config = snapshot / ".cargo/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        registry_url = (registry / "index").resolve().as_uri()
        config.write_text(
            f'[registries.rss-candidate]\nindex = "{registry_url}"\n', encoding="utf-8"
        )
        rewrite_dependencies(snapshot, dependencies, bundle.packages, env)
        materialize_conformance_fixture(snapshot, candidate)
        prepare_candidate_lock(snapshot, env)
        rewritten = cargo_metadata(snapshot, env, offline=True, no_deps=True)
        validate_rewritten_dependencies(
            dependencies, rewritten, bundle, f"registry+{registry_url}"
        )
        validate_conformance_fixture_dependency(
            rewritten, bundle, candidate, f"registry+{registry_url}"
        )
        metadata = cargo_metadata(snapshot, env, offline=True, no_deps=False)
        consumed = validate_resolution(
            snapshot, bundle, metadata, f"registry+{registry_url}"
        )
        run_visible(
            ["cargo", "fmt", "--all", "--", "--check"],
            snapshot,
            env,
            "candidate workspace fmt",
        )
        for subcommand, extra in (
            ("check", []),
            ("test", []),
            ("clippy", ["--", "-D", "warnings"]),
        ):
            run_visible(
                [
                    "cargo",
                    subcommand,
                    "--workspace",
                    "--all-targets",
                    "--locked",
                    "--offline",
                    *extra,
                ],
                snapshot,
                env,
                f"candidate workspace {subcommand}",
            )
        lock_sha = hashlib.sha256((snapshot / "Cargo.lock").read_bytes()).hexdigest()
        incubator_revision = run_capture(
            ["/usr/bin/git", "rev-parse", "HEAD"],
            repository,
            os.environ.copy(),
            "read incubator revision",
        ).decode().strip()
        return {
            "schemaVersion": 1,
            "rssRevision": bundle.rss_revision,
            "incubatorRevision": incubator_revision,
            "packages": [
                {"name": package.name, "version": package.version, "checksum": package.checksum}
                for package in bundle.packages
            ],
            "consumedPackages": consumed,
            "candidateLockSha256": lock_sha,
        }


def parse_args(argv):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--bundle", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    repository = Path(__file__).resolve().parent.parent
    bundle_root = args.bundle
    if not bundle_root.is_absolute():
        raise ProofError("--bundle must be an absolute path")
    before = git_status(repository)
    previous_handlers = {}

    def interrupted(signum, _frame):
        raise ProofError(f"candidate proof interrupted by signal {signum}")

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, interrupted)
    error = None
    summary = None
    try:
        summary = execute(repository, bundle_root)
    except Exception as caught:  # preserve cleanup/status evidence before reporting
        error = caught
    after = git_status(repository)
    for signum, handler in previous_handlers.items():
        signal.signal(signum, handler)
    if after != before:
        raise ProofError("candidate proof changed the real incubator checkout")
    if error is not None:
        if isinstance(error, ProofError):
            raise error
        raise ProofError(str(error)) from error
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except ProofError as error:
        print(f"candidate-proof: {error}", file=sys.stderr)
        raise SystemExit(1)
