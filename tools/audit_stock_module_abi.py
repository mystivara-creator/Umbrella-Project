#!/usr/bin/env python3
"""Compare stock module imported CRCs against provider-aware Kleaf exports.

Input is metadata only; never upload proprietary stock .ko binaries.
A symbol exported by multiple providers with differing CRCs is ambiguous,
even when one provider happens to match the stock import.
"""
import argparse
import json
from pathlib import Path


def read_exports(paths):
    exports = {}
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            crc, symbol, provider = fields[:3]
            exports.setdefault(symbol, set()).add((provider, crc.lower()))
    return exports


def normalize_modules(data):
    modules = data.get("modules", data) if isinstance(data, dict) else data
    if isinstance(modules, dict):
        modules = [{"module": name, **value} for name, value in modules.items()]
    if not isinstance(modules, list):
        raise ValueError("Baseline must contain a modules list or mapping")
    result = []
    if not modules:
        raise ValueError("Stock ABI baseline contains no modules")
    for item in modules:
        name = item.get("module") or item.get("name") or item.get("path")
        imports = item.get("imported_symbols")
        if not isinstance(name, str) or not isinstance(imports, dict):
            raise ValueError("Each module needs module/name and imported_symbols mapping")
        if not imports:
            raise ValueError(f"Stock ABI module has no imported CRCs: {name}")
        result.append((name, imports, item.get("vermagic", "")))
    return result


def compare(baseline, exports):
    records = []
    counts = {"matched": 0, "crc_mismatch": 0, "missing_export": 0,
              "ambiguous_export": 0, "unversioned": 0}
    for module, imports, vermagic in normalize_modules(baseline):
        for symbol, stock_crc in sorted(imports.items()):
            providers = sorted(exports.get(symbol, set()))
            if not stock_crc:
                status = "unversioned"
            elif not providers:
                status = "missing_export"
            elif len({crc for _, crc in providers}) > 1:
                status = "ambiguous_export"
            elif providers[0][1] != str(stock_crc).lower():
                status = "crc_mismatch"
            else:
                status = "matched"
            counts[status] += 1
            if status != "matched":
                records.append({"module": module, "symbol": symbol,
                                "stock_crc": stock_crc, "status": status,
                                "providers": [{"module": p, "crc": c} for p, c in providers]})
    return {"module_count": len(normalize_modules(baseline)),
            "import_count": sum(counts.values()), "counts": counts,
            "findings": records, "compatible": not any(
                counts[k] for k in ("crc_mismatch", "missing_export",
                                     "ambiguous_export", "unversioned"))}


def audit(baseline_path, dist_dir):
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    exports = read_exports([Path(dist_dir) / "gki.Module.symvers",
                            Path(dist_dir) / "Module.symvers"])
    result = compare(baseline, exports)
    # Keep provider identity and input provenance visible. In mixed GKI/vendor
    # builds the same module path can occur in both tables with different CRCs;
    # choosing whichever CRC matches stock would hide an unresolved install policy.
    groups = {}
    for finding in result["findings"]:
        if finding["status"] != "crc_mismatch":
            continue
        for provider in finding["providers"]:
            group = groups.setdefault(provider["module"], {
                "import_count": 0, "symbols": set(), "consumers": set()})
            group["import_count"] += 1
            group["symbols"].add(finding["symbol"])
            group["consumers"].add(finding["module"])
    result["crc_mismatches_by_provider"] = {
        name: {"import_count": group["import_count"],
               "symbols": sorted(group["symbols"]),
               "consumers": sorted(group["consumers"])}
        for name, group in sorted(groups.items())}
    ambiguous = {f["symbol"] for f in result["findings"]
                 if f["status"] == "ambiguous_export"}
    conflicts = {symbol: [] for symbol in sorted(ambiguous)}
    for filename in ("gki.Module.symvers", "Module.symvers"):
        table = read_exports([Path(dist_dir) / filename])
        for symbol in sorted(ambiguous):
            conflicts[symbol].extend(
                {"source": filename, "module": provider, "crc": crc}
                for provider, crc in sorted(table.get(symbol, set())))
    result["ambiguous_export_sources"] = conflicts
    result["baseline_sha256"] = __import__("hashlib").sha256(
        Path(baseline_path).read_bytes()).hexdigest()
    result["export_symbol_count"] = len(exports)
    result["export_sources_present"] = {
        name: (Path(dist_dir) / name).is_file()
        for name in ("gki.Module.symvers", "Module.symvers")}
    if not all(result["export_sources_present"].values()):
        result["compatible"] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--dist-dir", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    report = audit(args.baseline, args.dist_dir)
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0 if report["compatible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

