"""Retain the qualified stock public certificate using upstream keyring support."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import ssl
import tempfile


def certificate_der(path):
    text = Path(path).read_text().strip()
    if (not text.startswith("-----BEGIN CERTIFICATE-----")
            or not text.endswith("-----END CERTIFICATE-----")
            or text.count("-----BEGIN CERTIFICATE-----") != 1 or "PRIVATE KEY" in text):
        raise ValueError("Expected exactly one public X.509 certificate")
    return ssl.PEM_cert_to_DER_cert(text)


def audit_trust_policy(root, policy):
    for key in ("certificate_path", "patch_path", "kernel_certificate_path"):
        path = PurePosixPath(policy[key])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Unsafe GKI module trust path")
    if not policy["kernel_certificate_path"].startswith("certs/"):
        raise ValueError("GKI public certificate must be under certs/")
    if hashlib.sha256(certificate_der(root / policy["certificate_path"])).hexdigest() != policy["certificate_sha256"]:
        raise ValueError("Qualified public certificate checksum mismatch")
    if hashlib.sha256((root / policy["patch_path"]).read_bytes()).hexdigest() != policy["patch_sha256"]:
        raise ValueError("GKI module trust patch checksum mismatch")


def check_kernel_source(root, policy):
    if hashlib.sha256(certificate_der(root / policy["kernel_certificate_path"])).hexdigest() != policy["certificate_sha256"]:
        raise ValueError("Kernel source does not contain the qualified public certificate")
    config = (root / "arch/arm64/configs/gki_defconfig").read_text().splitlines()
    for line in ("CONFIG_MODULE_SIG=y", "CONFIG_MODULE_SIG_PROTECT=y",
                 "CONFIG_SYSTEM_TRUSTED_KEYS=" + json.dumps(policy["kernel_certificate_path"])):
        if line not in config:
            raise ValueError("GKI trust source configuration missing: " + line)


def inspect_image(image, policy):
    # Local imports keep the artifact verifier and policy audit independent.
    from audit_core_module_policy import embedded_certificate_keys
    from verify_build_artifacts import extract_embedded_kconfig, parse_kconfig
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "config"
        config.write_bytes(extract_embedded_kconfig(image))
        values = parse_kconfig(config)
    expected = {"CONFIG_MODULE_SIG": "y", "CONFIG_MODULE_SIG_PROTECT": "y",
                "CONFIG_SYSTEM_TRUSTED_KEYRING": "y",
                "CONFIG_SYSTEM_TRUSTED_KEYS": json.dumps(policy["kernel_certificate_path"])}
    if any(values.get(k) != v for k, v in expected.items()):
        raise ValueError("Embedded GKI configuration does not preserve qualified module trust")
    certificates = embedded_certificate_keys(Path(image).read_bytes())
    found = [c for c in certificates if c["certificate_sha256"] == policy["certificate_sha256"]
             and c["public_key_sha256"] == policy["public_key_sha256"]]
    if not found:
        raise ValueError("Qualified stock signing certificate is absent from built Image")
    return {"qualified_stock_certificate_present": True,
            "certificate_sha256": policy["certificate_sha256"],
            "public_key_sha256": policy["public_key_sha256"],
            "embedded_config_checked": True, "hardware_module_loading_verified": False}
