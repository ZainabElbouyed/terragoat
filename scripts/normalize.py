#!/usr/bin/env python3
"""
normalize.py

Normalise et fusionne les résultats de Checkov et Trivy en un schéma
commun unique (JSON), avec déduplication basique.

Usage :
    python scripts/normalize.py \
        --checkov results/aws/checkov_results.json \
        --trivy   results/aws/trivy_results.json \
        --output  results/aws/unified_findings.json

Ce script ne fait AUCUNE hypothèse sur le provider : il traite
uniquement les deux fichiers JSON qu'on lui donne en argument, ce qui
permet de le réutiliser tel quel pour aws/azure/gcp/oracle/alicloud
simplement en changeant les chemins passés en argument (voir le
workflow GitHub Actions).
"""

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_KEYS = [
    "tool", "check_id", "title", "severity", "status",
    "file", "line", "resource", "message", "resolution",
    "references", "check_type", "raw",
]


def normalize_path(p):
    """Uniformise les chemins : enlève \\ et / initiaux, uniformise les slashs."""
    if not p:
        return ""
    return re.sub(r"^[\\/]+", "", p).replace("\\", "/")


def parse_trivy(data):
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        result_type = (result.get("Type") or "").lower()

        for m in result.get("Misconfigurations", []):
            findings.append({
                "tool": "trivy",
                "check_id": m.get("ID"),
                "title": m.get("Title"),
                "severity": (m.get("Severity") or "UNKNOWN").upper(),
                "status": (m.get("Status") or "FAIL").upper(),
                "file": normalize_path(target),
                "line": (m.get("CauseMetadata") or {}).get("StartLine"),
                "resource": m.get("Resource") or (m.get("CauseMetadata") or {}).get("Resource"),
                "message": m.get("Message") or m.get("Description"),
                "resolution": m.get("Resolution"),
                "references": m.get("References") or [],
                "check_type": result_type,
                "raw": m,
            })
    return findings


def normalize_checkov_block(block):
    ct = block.get("check_type", "unknown")
    results = block.get("results", {})
    out = []

    def build(c, status, refs=None):
        return {
            "tool": "checkov",
            "check_id": c.get("check_id"),
            "title": c.get("check_name"),
            "severity": (c.get("severity") or "UNKNOWN").upper(),
            "status": status,
            "file": normalize_path(c.get("file_path", "")),
            "line": (c.get("file_line_range") or [None])[0],
            "resource": c.get("resource"),
            "message": c.get("check_name"),
            "resolution": None,
            "references": refs or [],
            "check_type": ct,
            "raw": c,
        }

    for c in results.get("passed_checks", []):
        refs = [c.get("guideline")] if c.get("guideline") else []
        out.append(build(c, "PASS", refs))

    for c in results.get("failed_checks", []):
        refs = [c.get("guideline")] if c.get("guideline") else []
        out.append(build(c, "FAIL", refs))

    for c in results.get("skipped_checks", []):
        out.append(build(c, "SKIP", []))

    return out


def parse_checkov(checkov_raw):
    findings = []
    blocks = checkov_raw if isinstance(checkov_raw, list) else [checkov_raw]
    for block in blocks:
        findings.extend(normalize_checkov_block(block))
    return findings


def dedup_key(f):
    """
    Clé de dédup : même outil + check_id + fichier + ligne + status +
    ressource + type. Le check_id reste spécifique à l'outil, donc deux
    outils ne se dédupliquent JAMAIS entre eux (voulu : on garde la
    traçabilité de l'outil source).
    """
    return (
        f["tool"],
        f["check_id"],
        f["file"],
        f["line"] or 0,
        f["status"],
        f["resource"] or "",
        f["check_type"],
    )


def build_meta(trivy_findings, checkov_findings, all_findings, normalized, sources):
    return {
        "scope": "all",
        "schema_version": "1.0",
        "sources": sources,
        "counts": {
            "trivy": len(trivy_findings),
            "checkov": len(checkov_findings),
            "before_dedup": len(all_findings),
            "unified": len(normalized),
        },
        "by_status": {
            s: sum(1 for f in normalized if f["status"] == s)
            for s in ["PASS", "FAIL", "SKIP", "IGNORE", "UNKNOWN"]
        },
        "by_severity": {
            s: sum(1 for f in normalized if f["severity"] == s)
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        },
        "by_tool": {
            t: sum(1 for f in normalized if f["tool"] == t)
            for t in ["trivy", "checkov"]
        },
        "by_check_type": {
            ct: sum(1 for f in normalized if f["check_type"] == ct)
            for ct in sorted({f["check_type"] for f in normalized})
        } if normalized else {},
        "by_file": {
            fp: sum(1 for f in normalized if f["file"] == fp)
            for fp in sorted({f["file"] for f in normalized})
        } if normalized else {},
    }


def main():
    parser = argparse.ArgumentParser(description="Normalise les résultats Checkov + Trivy.")
    parser.add_argument("--checkov", required=True, type=Path, help="Chemin vers checkov_results.json")
    parser.add_argument("--trivy", required=True, type=Path, help="Chemin vers trivy_results.json")
    parser.add_argument("--output", required=True, type=Path, help="Chemin de sortie unified_findings.json")
    args = parser.parse_args()

    if not args.checkov.exists():
        print(f"⚠️  Fichier Checkov introuvable : {args.checkov} (on continue avec 0 alerte Checkov)", file=sys.stderr)
        checkov_raw = []
    else:
        checkov_raw = json.loads(args.checkov.read_text(encoding="utf-8"))

    if not args.trivy.exists():
        print(f"⚠️  Fichier Trivy introuvable : {args.trivy} (on continue avec 0 alerte Trivy)", file=sys.stderr)
        trivy_raw = {"Results": []}
    else:
        trivy_raw = json.loads(args.trivy.read_text(encoding="utf-8"))

    trivy_findings = parse_trivy(trivy_raw)
    checkov_findings = parse_checkov(checkov_raw)

    all_findings = trivy_findings + checkov_findings

    seen = {}
    for f in all_findings:
        k = dedup_key(f)
        if k not in seen:
            seen[k] = f
    unified = list(seen.values())

    normalized = [{k: f.get(k) for k in REQUIRED_KEYS} for f in unified]

    sources = {"trivy": str(args.trivy), "checkov": str(args.checkov)}
    meta = build_meta(trivy_findings, checkov_findings, all_findings, normalized, sources)

    output = {"meta": meta, "findings": normalized}

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    # Résumé sur stdout, utile dans les logs GitHub Actions
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
