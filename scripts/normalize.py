#!/usr/bin/env python3
"""
normalize.py — Normalise et fusionne les résultats de KICS et Trivy.
Usage :
    python scripts/normalize.py \
        --kics  results/aws/kics_results.json \
        --trivy results/aws/trivy_results.json \
        --provider aws \
        --output results/aws/unified_findings.json
"""
import argparse, json, re, sys
from pathlib import Path

REQUIRED_KEYS = [
    "tool", "check_id", "title", "severity", "status",
    "file", "line", "resource", "message", "resolution",
    "references", "check_type", "raw",
]


def normalize_path(p, provider=None):
    """Uniformise les chemins vers terraform/<provider>/<fichier>."""
    if not p or p.strip() in (".", "./"):
        return ""

    p = p.replace("\\", "/")
    p = re.sub(r"^(\.\./|\./)+", "", p)
    p = re.sub(r"^/+", "", p)
    p = re.sub(r"^path/", "", p)

    if provider and p.startswith(f"terraform/{provider}/"):
        p = p[len(f"terraform/{provider}/"):]

    if provider:
        return f"terraform/{provider}/{p}" if p else ""
    return p


def infer_check_type(file_path):
    """Déduit le type à partir du nom du fichier."""
    if not file_path:
        return "unknown"
    fname = Path(file_path).name.lower()
    if fname == "dockerfile" or fname.startswith("dockerfile."):
        return "dockerfile"
    ext = Path(file_path).suffix.lower()
    return {
        ".tf": "terraform",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".dockerfile": "dockerfile",
    }.get(ext, "unknown")


def parse_trivy(data, provider="aws"):
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        result_type = (result.get("Type") or "").lower()

        if target.strip() in (".", "./"):
            continue

        for m in result.get("Misconfigurations", []):
            findings.append({
                "tool": "trivy",
                "check_id": m.get("ID"),
                "title": m.get("Title"),
                "severity": (m.get("Severity") or "UNKNOWN").upper(),
                "status": (m.get("Status") or "FAIL").upper(),
                "file": normalize_path(target, provider),
                "line": (m.get("CauseMetadata") or {}).get("StartLine"),
                "resource": m.get("Resource") or (m.get("CauseMetadata") or {}).get("Resource"),
                "message": m.get("Message") or m.get("Description"),
                "resolution": m.get("Resolution"),
                "references": m.get("References") or [],
                "check_type": result_type,
                "raw": m,
            })
    return findings


def parse_kics(data, provider="aws"):
    findings = []
    for q in data.get("queries", []):
        severity = (q.get("severity") or "UNKNOWN").upper()
        title = q.get("query_name")
        desc = q.get("description") or title
        url = q.get("query_url")

        for f in q.get("files", []):
            fname = f.get("file_name", "")
            remediation = f.get("remediation") or None

            findings.append({
                "tool": "kics",
                "check_id": q.get("query_id"),
                "title": title,
                "severity": severity,
                "status": "FAIL",
                "file": normalize_path(fname, provider),
                "line": f.get("line"),
                "resource": f.get("resource_name") or f.get("search_key"),
                "message": desc,
                "resolution": remediation,
                "references": [url] if url else [],
                "check_type": infer_check_type(fname),
                "raw": {"query": q, "file": f},
            })
    return findings


def dedup_key(f):
    return (
        f["tool"], f["check_id"], f["file"], f["line"] or 0,
        f["status"], f["resource"] or "", f["check_type"],
    )


def build_meta(trivy_findings, kics_findings, all_findings, normalized, sources):
    return {
        "scope": "all",
        "schema_version": "1.0",
        "sources": sources,
        "counts": {
            "trivy": len(trivy_findings),
            "kics": len(kics_findings),
            "before_dedup": len(all_findings),
            "unified": len(normalized),
        },
        "by_status": {s: sum(1 for f in normalized if f["status"] == s)
                      for s in ["PASS", "FAIL", "SKIP", "IGNORE", "UNKNOWN"]},
        "by_severity": {s: sum(1 for f in normalized if f["severity"] == s)
                        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]},
        "by_tool": {t: sum(1 for f in normalized if f["tool"] == t)
                    for t in ["trivy", "kics"]},
        "by_check_type": {ct: sum(1 for f in normalized if f["check_type"] == ct)
                          for ct in sorted({f["check_type"] for f in normalized})} if normalized else {},
        "by_file": {fp: sum(1 for f in normalized if f["file"] == fp)
                    for fp in sorted({f["file"] for f in normalized})} if normalized else {},
    }


def main():
    parser = argparse.ArgumentParser(description="Normalise les résultats KICS + Trivy.")
    parser.add_argument("--kics", required=True, type=Path)
    parser.add_argument("--trivy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--provider", default="aws", help="Provider Terraform (aws, azure, gcp, ...)")
    args = parser.parse_args()

    if not args.kics.exists():
        print(f"⚠️  KICS introuvable : {args.kics}", file=sys.stderr)
        kics_raw = {"queries": []}
    else:
        kics_raw = json.loads(args.kics.read_text(encoding="utf-8"))

    if not args.trivy.exists():
        print(f"⚠️  Trivy introuvable : {args.trivy}", file=sys.stderr)
        trivy_raw = {"Results": []}
    else:
        trivy_raw = json.loads(args.trivy.read_text(encoding="utf-8"))

    trivy_findings = parse_trivy(trivy_raw, args.provider)
    kics_findings = parse_kics(kics_raw, args.provider)
    all_findings = trivy_findings + kics_findings

    seen = {}
    for f in all_findings:
        k = dedup_key(f)
        if k not in seen:
            seen[k] = f
    unified = list(seen.values())

    normalized = [{k: f.get(k) for k in REQUIRED_KEYS} for f in unified]

    sources = {"trivy": str(args.trivy), "kics": str(args.kics), "provider": args.provider}
    meta = build_meta(trivy_findings, kics_findings, all_findings, normalized, sources)

    output = {"meta": meta, "findings": normalized}

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=" * 60)
    print(f"Normalisation terminée → {args.output}")
    print("=" * 60)
    for k, v in meta["counts"].items():
        print(f"  {k:15s} : {v}")
    print("Par statut     :", meta["by_status"])
    print("Par sévérité   :", meta["by_severity"])
    print("Par outil      :", meta["by_tool"])
    print("Par check_type :", meta["by_check_type"])

    fail_count = meta["by_status"].get("FAIL", 0)
    if fail_count > 0:
        print(f"\n{fail_count} alerte(s) FAIL détectée(s).")


if __name__ == "__main__":
    main()
