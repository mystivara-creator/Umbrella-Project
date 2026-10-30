#!/usr/bin/env python3
"""Umbrella Kernel Build & Source Tree Engineering Console (Redmi Note 15 5G / kunzite)."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"

# Delta files on top of remote HEAD d2de191f161f1d056847ba9dfc1a32ebde217c32
REPO_DELTA_FILES = [
    ".gitignore",
    ".github/workflows/kernel-build.yml",
    "README.md",
    "docs/UPSTREAM.md",
    "tools/source_audit.py",
    "tools/setup_kleaf_workspace.py",
    "tools/import_kernel_tree.py",
    "tests/test_kernel_tree_import.py",
]

VERIFIED_BAZEL_TARGETS = [
    {
        "label": "//common:kernel_aarch64",
        "rule": "kernel_build (in-repo root when imported via --role common)",
        "role": "Compiles Linux 6.6.118-android15-8 Image (arch/arm64, kernel/sched, mm, fs, block, certs) & frozen KMI Module.symvers",
    },
    {
        "label": "//common:kernel_aarch64_images",
        "rule": "kernel_images",
        "role": "Packages boot.img (header v4), init_boot.img, and system_dlkm images for GKI core",
    },
    {
        "label": "//msm-kernel:kunzite_perf",
        "rule": "define_kunzite -> define_msm_la (mixed build)",
        "role": "Compiles Qualcomm parrot + Xiaomi kunzite vendor .ko modules and 11 DTBs + kunzite-sm6475-overlay.dtbo against //common:kernel_aarch64",
    },
    {
        "label": "//msm-kernel:kunzite_perf_build_config",
        "rule": "kernel_build_config",
        "role": "Merges gki_defconfig + vendor/parrot_GKI.config + vendor/xiaomi/sm6475_common.config + vendor/kunzite_perf.config",
    },
    {
        "label": "//msm-kernel:kunzite_perf_images",
        "rule": "kernel_images",
        "role": "Builds vendor_boot.img, dtbo.img, and vendor_dlkm.img from kunzite_perf modules & DTBOs",
    },
    {
        "label": "//msm-kernel/arch/arm64/boot/dts/vendor:msm_dt",
        "rule": "dtstree (qcom/platform_map.bzl['kunzite'])",
        "role": "Compiles 11 parrot/ravelin base DTBs and kunzite-sm6475-overlay.dtbo via @dtc",
    },
]


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def run_gate(name: str, cmd: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return {
        "name": name,
        "command": " ".join(cmd),
        "passed": proc.returncode == 0,
        "exit_code": proc.returncode,
        "output": proc.stdout.strip(),
    }


def build_termux_apply_script() -> str:
    lines = [
        "#!/data/data/com.termux/files/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Umbrella Project — In-Repo Kernel Source Tree Transition Kit",
        "# Base commit: d2de191f161f1d056847ba9dfc1a32ebde217c32",
        "",
        'REPO_DIR="${1:-$(pwd)}"',
        'cd "$REPO_DIR"',
        "",
        'if [ ! -d ".git" ] || [ ! -f "config/devices/kunzite-global.json" ]; then',
        '  echo "ERROR: Run this script inside your local Umbrella-Project git clone." >&2',
        "  exit 1",
        "fi",
        "",
        'echo "=== Applying 8 SHA-256-verified Source Tree Transition files in $REPO_DIR ==="',
    ]

    for rel_path in REPO_DELTA_FILES:
        raw = (ROOT / rel_path).read_bytes()
        digest = sha256_bytes(raw)
        b64 = base64.b64encode(raw).decode("ascii")
        wrapped = "\n".join(b64[i : i + 76] for i in range(0, len(b64), 76))
        parent = str(Path(rel_path).parent)
        if parent != ".":
            lines.append(f'mkdir -p "{parent}"')
        lines.extend(
            [
                f'base64 -d <<\'EOF_B64\' > "{rel_path}"',
                wrapped,
                "EOF_B64",
                f'echo "{digest}  {rel_path}" | sha256sum -c -',
            ]
        )
        if rel_path.startswith("tools/") and rel_path.endswith(".py"):
            lines.append(f'chmod +x "{rel_path}"')

    lines.extend(
        [
            "",
            'echo "=== Running all Umbrella validation gates & regression tests ==="',
            "python3 tools/validate_foundation.py",
            "python3 tools/validate_device_baseline.py",
            "python3 tools/source_audit.py",
            "python3 tools/validate_regions.py",
            "python3 -m unittest discover -s tests -p 'test_*.py' -v",
            "",
            'echo "=== Step 1 complete: commit transition kit, then import real kernel tree ==="',
            "git status -s",
            'echo ""',
            'echo "1) Commit transition infrastructure:"',
            'echo "   git add .gitignore .github/workflows/kernel-build.yml README.md docs/UPSTREAM.md tools/source_audit.py tools/setup_kleaf_workspace.py tools/import_kernel_tree.py tests/test_kernel_tree_import.py"',
            'echo "   git commit -m \\"feat(tree): add verified Linux kernel baseline importer and Kleaf in-repo binding\\""',
            'echo ""',
            'echo "2) Populate real arch/, drivers/, include/, kernel/, mm/ from local Termux workspace:"',
            'echo "   python3 tools/import_kernel_tree.py --role common --local-source ~/umbrella-workspace/android-kernel/common"',
            'echo "   python3 tools/source_audit.py"',
            'echo "   git add -A && git commit -m \\"kernel: import pinned ACK 6.6.118-android15-8 baseline (e56cf6b09cca)\\""',
            'echo "   git push origin main"',
            "",
        ]
    )
    return "\n".join(lines)


def build_termux_import_command() -> str:
    return "\n".join(
        [
            "#!/data/data/com.termux/files/usr/bin/env bash",
            "set -euo pipefail",
            "",
            'REPO_DIR="${1:-$HOME/Umbrella-Project}"',
            'LOCAL_COMMON="${2:-$HOME/umbrella-workspace/android-kernel/common}"',
            'export TMPDIR="${TMPDIR:-$PREFIX/tmp}"',
            'mkdir -p "$TMPDIR"',
            "",
            'cd "$REPO_DIR"',
            'python3 tools/import_kernel_tree.py \\',
            "  --role common \\",
            '  --local-source "$LOCAL_COMMON"',
            "",
            "python3 tools/validate_foundation.py",
            "python3 tools/source_audit.py",
            "python3 -m unittest discover -s tests -p 'test_*.py' -v",
            "",
            'echo "=== Kernel source tree ready at $REPO_DIR (arch/, drivers/, include/, kernel/, mm/) ==="',
            "ls -d arch drivers include kernel mm fs block certs scripts tools/build",
            "",
        ]
    )


def compute_status_payload() -> dict[str, Any]:
    source_manifest = json.loads(
        (ROOT / "config/sources/kernel-source.json").read_text(encoding="utf-8")
    )
    device_baseline = json.loads(
        (ROOT / "config/devices/kunzite-global.json").read_text(encoding="utf-8")
    )
    wf_raw = (ROOT / ".github/workflows/kernel-build.yml").read_text(encoding="utf-8")
    if yaml is not None:
        wf_parsed = yaml.safe_load(wf_raw)
        triggers = wf_parsed.get("on") or wf_parsed.get(True) or {}
        trigger_names = list(triggers.keys()) if isinstance(triggers, dict) else []
    else:
        trigger_names = [
            t for t in ("workflow_dispatch", "push", "pull_request") if f"{t}:" in wf_raw
        ]

    gates = [
        run_gate("Foundation Gate", [sys.executable, "tools/validate_foundation.py"]),
        run_gate("Device Baseline Gate", [sys.executable, "tools/validate_device_baseline.py"]),
        run_gate("Source Provenance Gate", [sys.executable, "tools/source_audit.py"]),
        run_gate("Region Compatibility Gate", [sys.executable, "tools/validate_regions.py"]),
        run_gate(
            "Full Regression Suite (Build + Stock ABI + Module Policy + Tree Import)",
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        ),
    ]

    bundle_manifest = []
    for rel_path in REPO_DELTA_FILES:
        fp = ROOT / rel_path
        raw = fp.read_bytes()
        bundle_manifest.append(
            {
                "path": rel_path,
                "bytes": len(raw),
                "lines": len(raw.splitlines()),
                "sha256": sha256_bytes(raw),
            }
        )

    return {
        "all_gates_passed": all(g["passed"] for g in gates),
        "flash_approved": False,
        "in_repo_tree": source_manifest.get("in_repo_tree"),
        "device_baseline": device_baseline,
        "source_manifest": source_manifest,
        "remote_audit": {
            "repository": "mystivara-creator/Umbrella-Project",
            "default_branch": "main",
            "remote_head_sha": "d2de191f161f1d056847ba9dfc1a32ebde217c32",
            "ci_status": "Umbrella Kernel Build GREEN (runs #41030922231 & #41035617036); Foundation GREEN (#41109434115)",
            "findings": [
                "HEAD `d2de191f161f` (2026-10-30T18:44:06Z) withdrew `core-test01` after `fastboot boot` stalled ~3 minutes at the HyperOS logo (normal reboot cleanly restored stock 6.6.118; no partition flashed).",
                "Audit Gap #1 (`CONFIG_MODULE_SIG_PROTECT=y`): Stock Image embeds X.509 SPKI `0c0c619e...` while Kleaf built Image generated `c01291a0...`; retained stock GKI modules lose trusted status (`-EACCES` on GKI-protected symbols).",
                "Audit Gap #2 (Early-boot ramdisk modules): 102 of 443 loaded runtime modules (`clk_qcom`, `qcom_scm`, `ufs_qcom`, `sched_walt`, `metis`, `kernelsu`) reside in `vendor_boot`/`init_boot` ramdisks outside filesystem DLKM indices.",
                "Source Tree Transition Trap Prevented: Unanchored `build/` in legacy `.gitignore` would have silently ignored Linux `tools/build/` (breaking `objtool`/BTF), while upstream Linux `.*` in `.gitignore` would have masked `.github/workflows/` without explicit negations.",
            ],
        },
        "workflow_triggers": trigger_names,
        "verified_bazel_targets": VERIFIED_BAZEL_TARGETS,
        "gates": gates,
        "bundle_files": bundle_manifest,
    }


try:
    from fastapi import FastAPI
    from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

if HAS_FASTAPI:
    app = FastAPI(title="Umbrella Kernel Build & Provenance Console")
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        return compute_status_payload()

    @app.get("/api/bundle.sh", response_class=PlainTextResponse)
    async def bundle_sh() -> PlainTextResponse:
        return PlainTextResponse(
            content=build_termux_apply_script(),
            headers={"Content-Disposition": 'attachment; filename="apply-source-tree-kit.sh"'},
        )

    @app.get("/api/termux-overlay.sh", response_class=PlainTextResponse)
    async def termux_overlay_sh() -> PlainTextResponse:
        return PlainTextResponse(
            content=build_termux_import_command(),
            headers={"Content-Disposition": 'attachment; filename="import-kernel-tree-termux.sh"'},
        )

    @app.get("/", response_class=HTMLResponse)
    async def index():
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return HTMLResponse("<h1>Umbrella Kernel Build & Provenance Console</h1>")


class _FallbackHandler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, content_type: str, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/health":
            self._send(200, b'{"status":"ok"}', "application/json; charset=utf-8")
        elif path == "/api/status":
            payload = json.dumps(compute_status_payload()).encode("utf-8")
            self._send(200, payload, "application/json; charset=utf-8")
        elif path == "/api/bundle.sh":
            self._send(
                200,
                build_termux_apply_script().encode("utf-8"),
                "text/plain; charset=utf-8",
                {"Content-Disposition": 'attachment; filename="apply-source-tree-kit.sh"'},
            )
        elif path == "/api/termux-overlay.sh":
            self._send(
                200,
                build_termux_import_command().encode("utf-8"),
                "text/plain; charset=utf-8",
                {"Content-Disposition": 'attachment; filename="import-kernel-tree-termux.sh"'},
            )
        elif path == "/" or path == "/index.html":
            body = (STATIC_DIR / "index.html").read_bytes()
            self._send(200, body, "text/html; charset=utf-8")
        elif path.startswith("/static/"):
            rel = path.removeprefix("/static/")
            fp = (STATIC_DIR / rel).resolve()
            if fp.is_relative_to(STATIC_DIR.resolve()) and fp.is_file():
                ctype = mimetypes.guess_type(str(fp))[0] or "application/octet-stream"
                self._send(200, fp.read_bytes(), ctype)
            else:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    if HAS_FASTAPI:
        uvicorn.run(app, host="0.0.0.0", port=port)
    else:
        server = ThreadingHTTPServer(("0.0.0.0", port), _FallbackHandler)
        print(f"Umbrella Console listening on http://0.0.0.0:{port} (stdlib HTTP)")
        server.serve_forever()
