#!/usr/bin/env python3
"""Deterministic, fail-closed Linux kernel baseline importer for Umbrella-Project.

Populates Umbrella-Project root with the verified real Linux kernel source tree
(arch/, drivers/, include/, kernel/, mm/, fs/, block/, certs/, scripts/, tools/,
COPYING, Makefile, BUILD.bazel) from an exact pinned SHA-1 commit while:
- Enforcing docs/UPSTREAM.md presence per docs/SOURCE_POLICY.md
- Verifying exact 40-hex commit SHA-1 before extracting a single file
- Reusing an existing local git checkout (e.g. Termux ~/umbrella-workspace/android-kernel/common
  or ~/umbrella-sources/kunzite) without re-downloading gigabytes over the network
- Preserving Umbrella's README.md, .github/workflows/, config/, docs/, interfaces/,
  tests/, and tools/*.py / tools/*.sh
- Merging upstream Linux .gitignore safely so neither tools/build/ nor .github/workflows/
  is ever masked by gitignore rules
"""
import argparse
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from source_audit import REQUIRED_KERNEL_DIRS, audit_source_manifest, parse_makefile_version

UMBRELLA_PROTECTED_FILES = {
    "README.md",
    "CONTRIBUTING.md",
    ".gitignore",
}

UMBRELLA_GITIGNORE_FOOTER = """
# === Umbrella Project Governance, CI & Workspace Rules ===
/out/
/build/
/dist/
/.umbrella-workspace/
/bazel-*/
/umbrella-kunzite-test-baseline-*.tar.gz
!/.gitignore
!/.github/
!/.github/**
!/README.md
!/CONTRIBUTING.md
!/config/
!/config/**
!/docs/
!/docs/**
!/interfaces/
!/interfaces/**
!/patches/
!/patches/**
!/tests/
!/tests/**
!/tools/*.py
!/tools/*.sh
# Keep private configuration excluded after all governance negations.
/config/kernel/kunzite-stock.config
"""


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Command failed (exit {proc.returncode}): {' '.join(cmd)}\n{err}")
    return proc


def ensure_commit_available(
    source_repo: Path,
    remote_url: str,
    expected_sha: str,
    offline: bool = False,
) -> None:
    chk = subprocess.run(
        ["git", "cat-file", "-e", f"{expected_sha}^{{commit}}"],
        cwd=str(source_repo),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if chk.returncode == 0:
        return
    if offline:
        raise RuntimeError(
            f"Commit {expected_sha} is not present in local repository {source_repo} (--offline enabled)"
        )
    print(f"[fetch] Commit {expected_sha[:12]} not in {source_repo}; fetching from {remote_url}...")
    run(["git", "fetch", "--depth=1", "--no-tags", remote_url, expected_sha], cwd=source_repo)
    verify = subprocess.run(
        ["git", "cat-file", "-e", f"{expected_sha}^{{commit}}"],
        cwd=str(source_repo),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if verify.returncode != 0:
        raise RuntimeError(f"Fetched repository still missing commit {expected_sha}")


def extract_git_commit_to_dir(
    source_repo: Path,
    commit_sha: str,
    dest_dir: Path,
    preserve_protected: bool,
) -> tuple[str | None, str | None]:
    """Stream `git archive <commit_sha>` into dest_dir safely without touching protected Umbrella files."""
    resolved = run(["git", "rev-parse", f"{commit_sha}^{{commit}}"], cwd=source_repo).stdout.decode().strip()
    if resolved != commit_sha:
        raise RuntimeError(f"Commit SHA mismatch: expected {commit_sha}, resolved {resolved}")

    archive_bytes = run(["git", "archive", "--format=tar", commit_sha], cwd=source_repo).stdout
    upstream_gitignore: str | None = None
    upstream_readme: str | None = None

    dest_resolved = dest_dir.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as tf:
        for member in tf.getmembers():
            rel = member.name
            while rel.startswith("./"):
                rel = rel[2:]
            if rel in ("", "."):
                continue
            if rel.startswith("/") or ".." in PurePosixPath(rel).parts:
                raise RuntimeError(f"Unsafe tar path traversal blocked: {member.name}")
            target = (dest_resolved / rel).resolve()
            if not target.is_relative_to(dest_resolved):
                raise RuntimeError(f"Unsafe tar path traversal blocked: {member.name}")

            if preserve_protected and rel == ".gitignore" and member.isfile():
                fobj = tf.extractfile(member)
                if fobj is not None:
                    upstream_gitignore = fobj.read().decode("utf-8", errors="replace")
                continue
            if preserve_protected and rel == "README.md" and member.isfile():
                fobj = tf.extractfile(member)
                if fobj is not None:
                    upstream_readme = fobj.read().decode("utf-8", errors="replace")
                continue
            if preserve_protected and rel in UMBRELLA_PROTECTED_FILES:
                continue

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.symlink_to(member.linkname)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_symlink():
                    target.unlink()
                fobj = tf.extractfile(member)
                if fobj is None:
                    raise RuntimeError(f"Failed reading tar member: {rel}")
                target.write_bytes(fobj.read())
                if member.mode & 0o111:
                    target.chmod(0o755)

    return upstream_gitignore, upstream_readme


def merge_gitignore(upstream_gitignore: str | None, existing_gitignore: str) -> str:
    base = (upstream_gitignore or existing_gitignore).rstrip()
    if "=== Umbrella Project Governance, CI & Workspace Rules ===" in base:
        # Repair older generated footers without dropping user-added rules.
        if base.splitlines()[-1] != "/config/kernel/kunzite-stock.config":
            base += "\n/config/kernel/kunzite-stock.config"
        return base + "\n"
    return base + "\n" + UMBRELLA_GITIGNORE_FOOTER.lstrip("\n")


def import_tree(
    target_repo: Path,
    role: str,
    local_source: Path | None = None,
    local_devicetree_source: Path | None = None,
    allow_dirty: bool = False,
    offline: bool = False,
) -> dict[str, object]:
    target_repo = target_repo.expanduser().resolve()
    if not (target_repo / ".git").exists():
        raise RuntimeError(f"Target repository must be a Git checkout (.git missing): {target_repo}")

    upstream_doc = target_repo / "docs/UPSTREAM.md"
    if not upstream_doc.is_file() or not upstream_doc.read_text(encoding="utf-8").strip():
        raise RuntimeError("docs/UPSTREAM.md must exist before importing a kernel baseline (SOURCE_POLICY.md)")

    if not allow_dirty:
        dirty = run(["git", "status", "--porcelain"], cwd=target_repo).stdout.decode().strip()
        if dirty:
            raise RuntimeError(
                "Target Git working tree has uncommitted changes; commit or stash first before importing ~85k kernel files."
            )

    manifest_path = target_repo / "config/sources/kernel-source.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("in_repo_tree") is not None:
        raise RuntimeError(
            f"Repository already declares in_repo_tree={manifest['in_repo_tree']}; refusing duplicate import."
        )

    comp_key = "common_kernel" if role == "common" else "msm_kernel"
    comp = manifest["components"][comp_key]
    expected_sha = comp["commit"]
    remote_url = comp["repository"]

    with tempfile.TemporaryDirectory(prefix="umbrella-import-") as tmp:
        if local_source is not None:
            src_dir = local_source.expanduser().resolve()
            if not (src_dir / ".git").exists():
                raise RuntimeError(f"--local-source is not a git repository: {src_dir}")
            ensure_commit_available(src_dir, remote_url, expected_sha, offline=offline)
        else:
            if offline:
                raise RuntimeError("--offline requires --local-source")
            src_dir = Path(tmp) / comp_key
            src_dir.mkdir(parents=True)
            print(f"[clone] Fetching {comp_key} @ {expected_sha[:12]} from {remote_url}...")
            run(["git", "init", "-q"], cwd=src_dir)
            run(["git", "fetch", "--depth=1", "--no-tags", remote_url, expected_sha], cwd=src_dir)

        print(f"[extract] Importing {comp_key}@{expected_sha[:12]} into {target_repo}...")
        existing_gi = (target_repo / ".gitignore").read_text(encoding="utf-8") if (target_repo / ".gitignore").is_file() else ""
        up_gi, up_readme = extract_git_commit_to_dir(
            src_dir, expected_sha, target_repo, preserve_protected=True
        )
        (target_repo / ".gitignore").write_text(merge_gitignore(up_gi, existing_gi), encoding="utf-8")
        if up_readme:
            (target_repo / "docs/README.upstream-kernel.md").write_text(up_readme, encoding="utf-8")

        if comp_key == "common_kernel" and manifest.get("gki_module_trust"):
            from setup_kleaf_workspace import apply_component_patches
            from gki_module_trust import check_kernel_source
            apply_component_patches(target_repo, comp_key, target_repo)
            check_kernel_source(target_repo, manifest["gki_module_trust"])

        if comp_key == "msm_kernel":
            dt_comp = manifest["components"]["kernel_devicetree"]
            dt_sha = dt_comp["commit"]
            dt_url = dt_comp["repository"]
            if local_devicetree_source is not None:
                dt_src = local_devicetree_source.expanduser().resolve()
                if not (dt_src / ".git").exists():
                    raise RuntimeError(f"--local-devicetree-source is not a git repository: {dt_src}")
                ensure_commit_available(dt_src, dt_url, dt_sha, offline=offline)
            else:
                if offline:
                    raise RuntimeError("--offline with --role=msm-kernel requires --local-devicetree-source")
                dt_src = Path(tmp) / "kernel_devicetree"
                dt_src.mkdir(parents=True)
                print(f"[clone] Fetching kernel_devicetree @ {dt_sha[:12]} from {dt_url}...")
                run(["git", "init", "-q"], cwd=dt_src)
                run(["git", "fetch", "--depth=1", "--no-tags", dt_url, dt_sha], cwd=dt_src)

            dt_dest = target_repo / "arch/arm64/boot/dts/vendor"
            dt_dest.mkdir(parents=True, exist_ok=True)
            print(f"[extract] Importing kernel_devicetree@{dt_sha[:12]} -> arch/arm64/boot/dts/vendor...")
            extract_git_commit_to_dir(dt_src, dt_sha, dt_dest, preserve_protected=False)
            patch_dirs = ["patches/common_kernel"]
        else:
            patch_dirs = ["patches/msm_kernel", "patches/kernel_devicetree"]

        for pdir in patch_dirs:
            keep = target_repo / pdir / ".gitkeep"
            keep.parent.mkdir(parents=True, exist_ok=True)
            if not keep.exists():
                keep.write_text("", encoding="utf-8")

    linux_ver = parse_makefile_version(target_repo / "Makefile")
    manifest["in_repo_tree"] = {
        "role": comp_key,
        "upstream_repository": remote_url,
        "upstream_commit": expected_sha,
        "linux_version": linux_ver,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # Verify all required kernel directories & source_audit invariants
    audit_source_manifest(manifest, repo_root=target_repo)

    # Verify critical paths are NOT ignored by merged .gitignore
    for must_not_ignore in (
        "tools/build/Build",
        ".github/workflows/kernel-build.yml",
        "tools/source_audit.py",
        "config/sources/kernel-source.json",
    ):
        probe = target_repo / must_not_ignore
        if probe.exists():
            ign = subprocess.run(
                ["git", "check-ignore", "-q", must_not_ignore],
                cwd=str(target_repo),
                check=False,
            )
            if ign.returncode == 0:
                raise RuntimeError(f"Merged .gitignore erroneously ignores critical tracked path: {must_not_ignore}")

    return {
        "role": comp_key,
        "upstream_commit": expected_sha,
        "linux_version": linux_ver,
        "verified_dirs": list(REQUIRED_KERNEL_DIRS),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-repo",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path to Umbrella-Project Git checkout (default: repository root)",
    )
    parser.add_argument(
        "--role",
        choices=("common", "msm-kernel"),
        default="common",
        help="Upstream kernel baseline to establish at root ('common' = GKI 6.6.118 [recommended]; 'msm-kernel' = Xiaomi kunzite-v-oss 6.6.56)",
    )
    parser.add_argument(
        "--local-source",
        default="",
        help="Optional local Git checkout to reuse without network download (e.g. ~/umbrella-workspace/android-kernel/common)",
    )
    parser.add_argument(
        "--local-devicetree-source",
        default="",
        help="Optional local kernel_devicetree Git checkout when --role=msm-kernel",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow running on a dirty Git checkout (intended for automated test harnesses only)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Forbid network fetches; require pinned commit to exist in --local-source",
    )
    args = parser.parse_args()

    if shutil.which("git") is None:
        raise SystemExit("ERROR: git is required on PATH")

    summary = import_tree(
        target_repo=Path(args.target_repo),
        role=args.role,
        local_source=Path(args.local_source) if args.local_source else None,
        local_devicetree_source=Path(args.local_devicetree_source) if args.local_devicetree_source else None,
        allow_dirty=args.allow_dirty,
        offline=args.offline,
    )
    print(json.dumps({"status": "IMPORTED_AND_VERIFIED", **summary}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Kernel tree import FAIL: {exc}", file=sys.stderr)
        sys.exit(1)

