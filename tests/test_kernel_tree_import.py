#!/usr/bin/env python3
"""Unit and integration tests for in-repo Linux kernel source tree import and Kleaf binding."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import import_kernel_tree  # noqa: E402
import setup_kleaf_workspace  # noqa: E402
import source_audit  # noqa: E402


def git(cmd: list[str], cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *cmd],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def init_git_identity(repo: Path) -> None:
    git(["init", "-q"], repo)
    git(["config", "user.name", "Umbrella Test"], repo)
    git(["config", "user.email", "test@umbrella.local"], repo)


def create_synthetic_upstream_kernel_repo(path: Path, sublevel: int = 118, include_kunzite_bzl: bool = False) -> str:
    path.mkdir(parents=True, exist_ok=True)
    init_git_identity(path)

    (path / ".gitignore").write_text(
        "# SPDX-License-Identifier: GPL-2.0-only\n.*\n*.o\n*.ko\n!/.gitignore\n",
        encoding="utf-8",
    )
    (path / "README.md").write_text("# Upstream ACK Submission Guide\n", encoding="utf-8")
    (path / "COPYING").write_text("GPL-2.0 WITH Linux-syscall-note\n", encoding="utf-8")
    (path / "Kconfig").write_text('mainmenu "Linux/arm64 Kernel Configuration"\n', encoding="utf-8")
    (path / "Kbuild").write_text("# Kbuild root\n", encoding="utf-8")
    (path / "BUILD.bazel").write_text("# Kleaf kernel_aarch64 package\n", encoding="utf-8")
    (path / "Makefile").write_text(
        f"VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = {sublevel}\nEXTRAVERSION =\n",
        encoding="utf-8",
    )
    if include_kunzite_bzl:
        (path / "kunzite.bzl").write_text("def define_kunzite():\n    pass\n", encoding="utf-8")

    files = {
        "arch/arm64/Makefile": "# arm64 Makefile\n",
        "drivers/Makefile": "# drivers Makefile\n",
        "include/linux/kernel.h": "/* kernel.h */\n",
        "kernel/sched/core.c": "/* scheduler core */\n",
        "mm/vmscan.c": "/* memory reclaim */\n",
        "scripts/checkpatch.pl": "#!/usr/bin/env perl\n",
        "tools/build/Build": "# Linux tools/build feature detection\n",
    }
    for rel, content in files.items():
        fp = path / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")

    git(["add", "-f", "."], path)
    git(["commit", "-q", "-m", f"Linux 6.6.{sublevel} synthetic baseline"], path)
    return git(["rev-parse", "HEAD"], path)


def clone_umbrella_fixture(dest: Path, override_common_sha: str | None = None) -> None:
    shutil.copytree(
        ROOT,
        dest,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".umbrella-workspace",
            "app.py",
            "static",
            "metadata.json",
            "package.json",
            "requirements.txt",
        ),
    )
    if override_common_sha is not None:
        manifest_path = dest / "config/sources/kernel-source.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["components"]["common_kernel"]["commit"] = override_common_sha
        manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    init_git_identity(dest)
    git(["add", "."], dest)
    git(["commit", "-q", "-m", "Initial Umbrella metadata baseline"], dest)


class KernelTreeImportTests(unittest.TestCase):
    def test_import_common_kernel_tree_preserves_umbrella_and_unmasks_tools_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            upstream_common = tmp_path / "upstream-common"
            common_sha = create_synthetic_upstream_kernel_repo(upstream_common, sublevel=118)

            umbrella_repo = tmp_path / "Umbrella-Project"
            clone_umbrella_fixture(umbrella_repo, override_common_sha=common_sha)
            original_readme = (umbrella_repo / "README.md").read_text(encoding="utf-8")

            summary = import_kernel_tree.import_tree(
                target_repo=umbrella_repo,
                role="common",
                local_source=upstream_common,
            )
            self.assertEqual(summary["role"], "common_kernel")
            self.assertEqual(summary["upstream_commit"], common_sha)
            self.assertEqual(summary["linux_version"], "6.6.118")

            # Verify Umbrella files and imported Linux kernel directories coexist cleanly
            self.assertEqual((umbrella_repo / "README.md").read_text(encoding="utf-8"), original_readme)
            self.assertTrue((umbrella_repo / "docs/README.upstream-kernel.md").is_file())
            self.assertTrue((umbrella_repo / "arch/arm64/Makefile").is_file())
            self.assertTrue((umbrella_repo / "drivers/Makefile").is_file())
            self.assertTrue((umbrella_repo / "kernel/sched/core.c").is_file())
            self.assertTrue((umbrella_repo / "mm/vmscan.c").is_file())
            self.assertTrue((umbrella_repo / "tools/build/Build").is_file())
            self.assertTrue((umbrella_repo / "tools/source_audit.py").is_file())

            # Verify neither Linux tools/build/ nor .github/workflows/ is ignored
            for critical in ("tools/build/Build", ".github/workflows/kernel-build.yml", "tools/source_audit.py"):
                chk = subprocess.run(
                    ["git", "check-ignore", "-q", critical],
                    cwd=str(umbrella_repo),
                    check=False,
                )
                self.assertNotEqual(chk.returncode, 0, msg=f"{critical} must not be ignored by .gitignore")

            # Verify source_audit passes on the populated kernel source tree
            manifest = json.loads((umbrella_repo / "config/sources/kernel-source.json").read_text(encoding="utf-8"))
            source_audit.audit_source_manifest(manifest, repo_root=umbrella_repo)

            # Verify controlled Kleaf binding avoids .umbrella-workspace symlink loops
            ws_common = umbrella_repo / ".umbrella-workspace/android-kernel/common"
            prov = setup_kleaf_workspace.bind_in_repo_kernel_tree(umbrella_repo, ws_common)
            self.assertTrue(prov.startswith("in-repo:"))
            self.assertTrue((ws_common / "arch/arm64/Makefile").is_file())
            self.assertTrue((ws_common / ".git").exists())
            self.assertFalse((ws_common / ".umbrella-workspace").exists())

    def test_import_rejects_mismatched_commit_or_missing_upstream_doc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            upstream_common = tmp_path / "upstream-common"
            create_synthetic_upstream_kernel_repo(upstream_common, sublevel=118)

            umbrella_repo = tmp_path / "Umbrella-Project"
            # Leave default pinned SHA in manifest (which does not exist in synthetic repo)
            clone_umbrella_fixture(umbrella_repo, override_common_sha=None)

            with self.assertRaises(RuntimeError):
                import_kernel_tree.import_tree(
                    target_repo=umbrella_repo,
                    role="common",
                    local_source=upstream_common,
                    offline=True,
                )

            # Removing docs/UPSTREAM.md must fail closed per SOURCE_POLICY.md
            (umbrella_repo / "docs/UPSTREAM.md").unlink()
            git(["add", "-u"], umbrella_repo)
            git(["commit", "-q", "-m", "remove UPSTREAM.md"], umbrella_repo)
            with self.assertRaises(RuntimeError):
                import_kernel_tree.import_tree(
                    target_repo=umbrella_repo,
                    role="common",
                    local_source=upstream_common,
                    offline=True,
                )

    def test_apply_component_patches_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            vendor_repo = tmp_path / "msm-kernel"
            create_synthetic_upstream_kernel_repo(vendor_repo, sublevel=56, include_kunzite_bzl=True)

            # Create a real git diff patch against vendor_repo
            work = tmp_path / "patch-gen"
            shutil.copytree(vendor_repo, work)
            (work / "drivers/Makefile").write_text("# drivers Makefile\n# Umbrella vendor hook\n", encoding="utf-8")
            diff_text = git(["diff"], work) + "\n"

            umbrella_root = tmp_path / "umbrella"
            patch_dir = umbrella_root / "patches/msm_kernel"
            patch_dir.mkdir(parents=True)
            (patch_dir / "0001-umbrella-vendor-hook.patch").write_text(diff_text, encoding="utf-8")

            first = setup_kleaf_workspace.apply_component_patches(umbrella_root, "msm_kernel", vendor_repo)
            self.assertEqual(len(first), 1)
            self.assertIn("Umbrella vendor hook", (vendor_repo / "drivers/Makefile").read_text(encoding="utf-8"))

            # Re-applying on --reuse-existing must be idempotent
            second = setup_kleaf_workspace.apply_component_patches(umbrella_root, "msm_kernel", vendor_repo)
            self.assertEqual(len(second), 1)


if __name__ == "__main__":
    unittest.main()
