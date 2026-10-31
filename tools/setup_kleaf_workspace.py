#!/usr/bin/env python3
"""Deterministic, minimal Kleaf + Qualcomm/Xiaomi workspace assembler for kunzite.

Supports:
1. Fresh Linux x86_64 CI runners (minimal shallow checkout, ~5.4 GB vs 19 GB).
2. Existing local workspaces (e.g. Termux ~/umbrella-workspace/android-kernel) without
   re-downloading pre-synced AOSP repositories.
"""
import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from gki_module_trust import check_kernel_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE_MANIFEST = ROOT / "config/sources/kernel-source.json"

AOSP_BASE = "https://android.googlesource.com"

# Verified minimal set of AOSP Kleaf / Bzlmod / sysroot projects required to query and build
# //common:kernel_aarch64 and //msm-kernel:kunzite_perf* (excludes rust, virtual-device, wonder).
AOSP_MINIMAL_PROJECTS = [
    ("platform/build/bazel_common_rules", "build/bazel_common_rules", None),
    ("kernel/configs", "kernel/configs", "main"),
    ("platform/system/tools/mkbootimg", "tools/mkbootimg", None),
    ("platform/prebuilts/build-tools", "prebuilts/build-tools", None),
    ("platform/prebuilts/clang-tools", "prebuilts/clang-tools", None),
    (
        "platform/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8",
        "prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8",
        None,
    ),
    ("kernel/prebuilts/build-tools", "prebuilts/kernel-build-tools", None),
    ("platform/prebuilts/jdk/jdk11", "prebuilts/jdk/jdk11", None),
    ("platform/external/bazel-skylib", "external/bazel-skylib", None),
    ("platform/external/bazelbuild-bazel-central-registry", "external/bazelbuild-bazel-central-registry", None),
    ("platform/external/bazelbuild-platforms", "external/bazelbuild-platforms", None),
    ("platform/external/bazelbuild-apple_support", "external/bazelbuild-apple_support", None),
    ("platform/external/bazelbuild-rules_cc", "external/bazelbuild-rules_cc", None),
    ("platform/external/bazelbuild-rules_java", "external/bazelbuild-rules_java", None),
    ("platform/external/bazelbuild-rules_license", "external/bazelbuild-rules_license", None),
    ("platform/external/bazelbuild-rules_pkg", "external/bazelbuild-rules_pkg", None),
    ("platform/external/bazelbuild-rules_python", "external/bazelbuild-rules_python", None),
    ("platform/external/python/absl-py", "external/python/absl-py", None),
    ("platform/external/libcap", "external/libcap", None),
    ("platform/external/libcap-ng", "external/libcap-ng", None),
    ("platform/external/lz4", "external/lz4", None),
    ("platform/external/pigz", "external/pigz", None),
    ("platform/external/toybox", "external/toybox", None),
    ("platform/external/zlib", "external/zlib", None),
    ("platform/external/zopfli", "external/zopfli", None),
]


def run(cmd: list[str], cwd: Path | None = None) -> str:
    # Gitiles and large AOSP prebuilt fetches occasionally terminate mid-pack.
    # Retry only transient Git transport failures, never missing refs or SHA mismatches.
    import time

    git_network = len(cmd) > 1 and cmd[0] == "git" and cmd[1] in ("clone", "fetch")
    attempts = 4 if git_network else 1
    for attempt in range(attempts):
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            env={**os.environ, "GIT_HTTP_VERSION": "HTTP/1.1"} if git_network else None,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
        output = proc.stdout.lower()
        transient = any(token in output for token in (
            "early eof", "invalid index-pack output", "rpc failed",
            "remote end hung up", "connection reset", "connection timed out",
            "http/2 stream", "curl 56", "curl 92", "unexpected disconnect",
        ))
        if not git_network or not transient or attempt + 1 == attempts:
            raise RuntimeError(
                f"Command failed (exit {proc.returncode}): {' '.join(cmd)}\n{proc.stdout}"
            )
        wait = 3 * (attempt + 1)
        print(f"[git-retry] transient transport error; attempt {attempt + 2}/{attempts} in {wait}s", flush=True)
        time.sleep(wait)
    raise AssertionError("unreachable")


def git_head(repo_dir: Path) -> str:
    return run(["git", "rev-parse", "HEAD"], cwd=repo_dir)


def ensure_pinned_commit(name: str, repo_url: str, dest: Path, sha: str, reuse_existing: bool) -> str:
    if dest.is_symlink():
        resolved = dest.resolve()
        if resolved.exists() and (resolved / ".git").exists():
            actual = git_head(resolved)
            print(f"[reuse-symlink] {name}: {dest} -> {resolved} @ {actual[:12]}")
            return actual

    if (dest / ".git").exists():
        actual = git_head(dest)
        if actual == sha:
            print(f"[verified] {name}: {dest} already at {sha[:12]}")
            return actual
        if reuse_existing:
            print(f"[fetch-pin] {name}: updating {dest} from {actual[:12]} to {sha[:12]}")
            run(["git", "fetch", "--depth=1", repo_url, sha], cwd=dest)
            run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=dest)
            return git_head(dest)
        shutil.rmtree(dest)

    print(f"[clone-pin] {name}: {repo_url} @ {sha[:12]} -> {dest}")
    dest.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q"], cwd=dest)
    run(["git", "remote", "add", "origin", repo_url], cwd=dest)
    run(["git", "fetch", "--depth=1", "--no-tags", "origin", sha], cwd=dest)
    run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], cwd=dest)
    actual = git_head(dest)
    if actual != sha:
        raise RuntimeError(f"SHA mismatch for {name}: expected {sha}, got {actual}")
    return actual


def ensure_aosp_branch(repo_path: str, dest: Path, branch: str) -> str:
    if (dest / ".git").exists() or (dest.exists() and any(dest.iterdir())):
        if (dest / ".git").exists():
            return git_head(dest)
        return "existing-non-git"
    url = f"{AOSP_BASE}/{repo_path}"
    print(f"[clone-aosp] {repo_path} ({branch}) -> {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "git",
            "clone",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "--branch",
            branch,
            "-q",
            url,
            str(dest),
        ]
    )
    return git_head(dest)


def ensure_clang_prebuilt(ws: Path, branch: str, clang_version: str, query_only: bool) -> str:
    dest = ws / "prebuilts/clang/host/linux-x86"
    target_clang_dir = dest / f"clang-{clang_version}"
    kleaf_dir = dest / "kleaf"
    if dest.exists() and kleaf_dir.exists() and (query_only or target_clang_dir.exists()):
        if (dest / ".git").exists():
            return git_head(dest)
        return "existing-clang"

    if dest.exists():
        shutil.rmtree(dest)

    url = f"{AOSP_BASE}/platform/prebuilts/clang/host/linux-x86"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if query_only:
        print("[sparse-clone] prebuilts/clang/host/linux-x86 (query-only kleaf metadata)")
        run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                "--branch",
                branch,
                "-q",
                url,
                str(dest),
            ]
        )
        run(
            ["git", "sparse-checkout", "set", "--no-cone", "/BUILD.bazel", "/kleaf/**"],
            cwd=dest,
        )
        run(["git", "checkout", "-q"], cwd=dest)
        return git_head(dest)

    print(f"[clone-aosp] prebuilts/clang/host/linux-x86 (clang-{clang_version}, {branch})")
    run(
        [
            "git",
            "clone",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "--branch",
            branch,
            "-q",
            url,
            str(dest),
        ]
    )
    if not target_clang_dir.is_dir():
        raise RuntimeError(f"Expected toolchain directory missing: {target_clang_dir}")
    return git_head(dest)


def ensure_ndk_prebuilt(ws: Path, branch: str, query_only: bool) -> str:
    dest = ws / "prebuilts/ndk-r26"
    sysroot = dest / "toolchains/llvm/prebuilt/linux-x86_64/sysroot"
    if dest.exists() and (query_only or sysroot.exists()):
        if (dest / ".git").exists():
            return git_head(dest)
        return "existing-ndk"

    if dest.exists():
        shutil.rmtree(dest)

    dest.parent.mkdir(parents=True, exist_ok=True)
    if query_only:
        dest.mkdir(parents=True, exist_ok=True)
        return "stub-query-only"

    url = f"{AOSP_BASE}/toolchain/prebuilts/ndk/r26"
    print(f"[clone-aosp] prebuilts/ndk-r26 ({branch})")
    run(
        [
            "git",
            "clone",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "--branch",
            branch,
            "-q",
            url,
            str(dest),
        ]
    )
    return git_head(dest)


def ensure_dtc_in_bzlmod(ws: Path) -> None:
    """Ensure build/kernel/kleaf/bzlmod/bazel.MODULE.bazel registers @dtc."""
    mod_file = ws / "build/kernel/kleaf/bzlmod/bazel.MODULE.bazel"
    if not mod_file.is_file():
        raise RuntimeError(f"Missing Kleaf MODULE.bazel at {mod_file}")
    content = mod_file.read_text(encoding="utf-8")
    if 'name = "dtc"' in content:
        return
    print("[patch-bzlmod] Registering @dtc local repository in bazel.MODULE.bazel")
    dtc_block = (
        '\nnew_kleaf_local_repository(\n'
        '    name = "dtc",\n'
        '    build_file = "msm-kernel/BUILD.dtc",\n'
        '    path = "external/dtc",\n'
        ')\n'
    )
    marker = 'path = "prebuilts/ndk-r26",\n)'
    if marker in content:
        content = content.replace(marker, marker + dtc_block, 1)
    else:
        content += dtc_block
    mod_file.write_text(content, encoding="utf-8")


def force_symlink(target: str, link_path: Path) -> None:
    link_path.parent.mkdir(parents=True, exist_ok=True)
    if link_path.is_symlink() or link_path.is_file():
        link_path.unlink()
    os.symlink(target, link_path)


EXCLUDED_IN_REPO_ENTRIES = {
    ".umbrella-workspace",
    ".github",
    "patches",
    "app.py",
    "static",
    "metadata.json",
    "package.json",
    "requirements.txt",
    "__pycache__",
}


def detect_in_repo_role(umbrella_root: Path, manifest: dict) -> str | None:
    in_repo = manifest.get("in_repo_tree")
    if not isinstance(in_repo, dict):
        return None
    role = in_repo.get("role")
    if role not in ("common_kernel", "msm_kernel"):
        raise RuntimeError(f"Unsupported in_repo_tree.role: {role}")
    if not (umbrella_root / "Makefile").is_file() or not (umbrella_root / "arch/arm64").is_dir():
        raise RuntimeError(
            f"Manifest declares in_repo_tree ({role}), but {umbrella_root} lacks Makefile or arch/arm64"
        )
    return role


def bind_in_repo_kernel_tree(umbrella_root: Path, dest: Path) -> str:
    """Bind an in-repo kernel source tree into Kleaf workspace without recursive .umbrella-workspace loops."""
    umbrella_root = umbrella_root.resolve()
    if dest.is_symlink():
        dest.unlink()
    elif dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    for entry in sorted(umbrella_root.iterdir(), key=lambda p: p.name):
        if entry.name in EXCLUDED_IN_REPO_ENTRIES:
            continue
        os.symlink(entry, dest / entry.name)

    head = git_head(umbrella_root) if (umbrella_root / ".git").exists() else "working-tree"
    print(f"[bind-in-repo] {dest} -> {umbrella_root} ({head[:12]})")
    return f"in-repo:{head}"


def apply_component_patches(umbrella_root: Path, cname: str, repo_dir: Path) -> list[dict[str, str]]:
    import hashlib

    candidates = [
        umbrella_root / "patches" / cname,
        umbrella_root / "patches" / cname.replace("_", "-"),
    ]
    patch_files: list[Path] = []
    seen_dirs: set[Path] = set()
    for pdir in candidates:
        if pdir.is_dir() and pdir.resolve() not in seen_dirs:
            seen_dirs.add(pdir.resolve())
            patch_files.extend(sorted(pdir.glob("*.patch")))

    applied: list[dict[str, str]] = []
    for pfile in patch_files:
        digest = hashlib.sha256(pfile.read_bytes()).hexdigest()
        rev_chk = subprocess.run(
            ["git", "apply", "--reverse", "--check", str(pfile)],
            cwd=str(repo_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if rev_chk.returncode == 0:
            print(f"[patch-skip] {cname}: {pfile.name} already applied")
        else:
            print(f"[patch-apply] {cname}: applying {pfile.name}")
            run(["git", "apply", "--check", str(pfile)], cwd=repo_dir)
            run(["git", "apply", str(pfile)], cwd=repo_dir)
        applied.append({"component": cname, "patch": pfile.name, "sha256": digest})
    return applied


def wire_workspace_links(ws: Path) -> None:
    force_symlink("../build/kernel/kleaf/bazel.sh", ws / "tools/bazel")
    force_symlink("build/kernel/kleaf/bazel.WORKSPACE", ws / "WORKSPACE")
    force_symlink("build/kernel/kleaf/bzlmod/bazel.MODULE.bazel", ws / "MODULE.bazel")
    force_symlink("build/kernel/kleaf/bzlmod/bazel.WORKSPACE.bzlmod", ws / "WORKSPACE.bzlmod")
    force_symlink("common", ws / ".source_date_epoch_dir")
    force_symlink("../msm-kernel/msm_kernel_extensions.bzl", ws / "build/msm_kernel_extensions.bzl")

    build_pkg = ws / "build/BUILD.bazel"
    build_pkg.parent.mkdir(parents=True, exist_ok=True)
    build_pkg.write_text(
        '# Generated by Umbrella setup_kleaf_workspace.py\n'
        'exports_files(["msm_kernel_extensions.bzl"])\n',
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Setup minimal Kleaf + Xiaomi kunzite workspace")
    parser.add_argument("--workspace", required=True, help="Target Kleaf workspace directory")
    parser.add_argument(
        "--umbrella-root",
        default=str(ROOT),
        help="Path to Umbrella-Project root (auto-binds in-repo kernel tree when present)",
    )
    parser.add_argument(
        "--query-only",
        action="store_true",
        help="Skip downloading full Clang/NDK binaries (for fast Bazel target query verification)",
    )
    parser.add_argument(
        "--reuse-existing",
        action="store_true",
        help="Reuse existing synced workspace (e.g. Termux) without wiping non-matching git trees",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="Parallel git clone jobs (default: 4)",
    )
    parser.add_argument(
        "--min-free-gb",
        type=float,
        default=0.0,
        help="Fail early if free disk space on workspace filesystem is below threshold",
    )
    args = parser.parse_args()

    umbrella_root = Path(args.umbrella_root).expanduser().resolve()
    manifest_file = umbrella_root / "config/sources/kernel-source.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    in_repo_role = detect_in_repo_role(umbrella_root, manifest)

    ws = Path(args.workspace).expanduser().resolve()
    ws.mkdir(parents=True, exist_ok=True)

    disk = shutil.disk_usage(ws)
    free_gb = disk.free / (1024 ** 3)
    total_gb = disk.total / (1024 ** 3)
    print(f"[disk] Workspace {ws}: {free_gb:.2f} GiB free / {total_gb:.2f} GiB total")
    if args.min_free_gb > 0 and free_gb < args.min_free_gb:
        raise RuntimeError(
            f"Insufficient disk space: {free_gb:.2f} GiB free < required {args.min_free_gb:.2f} GiB"
        )

    components = manifest["components"]
    default_branch = manifest["aosp_kleaf_manifest_branch"]
    clang_version = manifest["clang_version"]
    provenance: dict[str, str] = {}
    applied_patches: list[dict[str, str]] = []

    if in_repo_role is not None:
        provenance[in_repo_role] = bind_in_repo_kernel_tree(
            umbrella_root, ws / components[in_repo_role]["path"]
        )

    primary_order = [c for c in ("kernel_build", "msm_kernel", "external_dtc") if c != in_repo_role]
    if in_repo_role != "common_kernel" and (not args.query_only or not (ws / "common/.git").exists()):
        primary_order.append("common_kernel")

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, 4)) as pool:
        fut_map = {
            pool.submit(
                ensure_pinned_commit,
                cname,
                components[cname]["repository"],
                ws / components[cname]["path"],
                components[cname]["commit"],
                args.reuse_existing,
            ): cname
            for cname in primary_order
        }
        for fut in concurrent.futures.as_completed(fut_map):
            cname = fut_map[fut]
            provenance[cname] = fut.result()

    dt_comp = components["kernel_devicetree"]
    dt_dest = ws / dt_comp["path"]
    if in_repo_role == "msm_kernel" and (umbrella_root / "arch/arm64/boot/dts/vendor/BUILD.bazel").is_file():
        provenance["kernel_devicetree"] = provenance["msm_kernel"]
    else:
        provenance["kernel_devicetree"] = ensure_pinned_commit(
            "kernel_devicetree",
            dt_comp["repository"],
            dt_dest,
            dt_comp["commit"],
            args.reuse_existing,
        )

    for cname in ("common_kernel", "msm_kernel", "kernel_devicetree"):
        if cname != in_repo_role and (ws / components[cname]["path"]).exists():
            applied_patches.extend(
                apply_component_patches(umbrella_root, cname, ws / components[cname]["path"])
            )

    if manifest.get("gki_module_trust"):
        check_kernel_source(ws / components["common_kernel"]["path"], manifest["gki_module_trust"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        aosp_futs = {
            pool.submit(
                ensure_aosp_branch,
                repo_path,
                ws / rel_dest,
                rev or default_branch,
            ): rel_dest
            for repo_path, rel_dest, rev in AOSP_MINIMAL_PROJECTS
        }
        for fut in concurrent.futures.as_completed(aosp_futs):
            rel_dest = aosp_futs[fut]
            provenance[rel_dest] = fut.result()

    provenance["prebuilts/clang/host/linux-x86"] = ensure_clang_prebuilt(
        ws, default_branch, clang_version, args.query_only
    )
    provenance["prebuilts/ndk-r26"] = ensure_ndk_prebuilt(
        ws, default_branch, args.query_only
    )

    ensure_dtc_in_bzlmod(ws)
    wire_workspace_links(ws)

    prov_path = ws / "workspace-provenance.json"
    prov_path.write_text(
        json.dumps(
            {
                "device": manifest["device"],
                "codename": manifest["codename"],
                "clang_version": clang_version,
                "in_repo_role": in_repo_role,
                "query_only": args.query_only,
                "applied_patches": applied_patches,
                "repositories": provenance,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"[ready] Workspace configured cleanly. Provenance written to {prov_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

