#!/usr/bin/env python3
"""
Quality gate de securite du pipeline DevSecOps.

Lit les rapports JSON de chaque scanner, normalise les resultats, applique la
politique (security/policy.yml) et les derogations tracees
(security/exemptions.yml), puis decide :  PASS  ou  BLOCK.

  check     --tool <outil>   verdict pour un seul outil (utilise par chaque stage)
  evaluate                   verdict global + rapports HTML/JSON + historique

Code de sortie : 0 = conforme, 1 = bloquant.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import sys
from pathlib import Path

import yaml

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
REPORT_FILES = {
    "gitleaks": "gitleaks.json",
    "semgrep": "semgrep.json",
    "bandit": "bandit.json",
    "trivy-fs": "trivy-fs.json",
    "trivy-image": "trivy-image.json",
    "zap": "zap.json",
    "checkov": "results_json.json",
    "sonarqube": "sonarqube-gate.json",
}


# ---------------------------------------------------------------- parsers
def _f(tool, rule, severity, title, location, **extra):
    return {"tool": tool, "rule": str(rule), "severity": severity, "title": title,
            "location": location, **extra}


def parse_gitleaks(data):
    for r in data or []:
        yield _f("gitleaks", r.get("RuleID"), "CRITICAL", r.get("Description", "Secret"),
                 f"{r.get('File')}:{r.get('StartLine')} (commit {str(r.get('Commit', ''))[:8]})",
                 fingerprint=r.get("Fingerprint"))


def parse_semgrep(data):
    sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    for r in data.get("results", []):
        ex = r.get("extra", {})
        yield _f("semgrep", r.get("check_id"), sev.get(ex.get("severity"), "MEDIUM"),
                 ex.get("message", "").strip().split("\n")[0][:160],
                 f"{r.get('path')}:{r.get('start', {}).get('line')}")


def parse_bandit(data):
    for r in data.get("results", []):
        yield _f("bandit", r.get("test_id"), r.get("issue_severity", "LOW").upper(),
                 r.get("issue_text", ""), f"{r.get('filename')}:{r.get('line_number')}",
                 confidence=r.get("issue_confidence", "LOW").upper())


def _parse_trivy(tool, data):
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            yield _f(tool, v.get("VulnerabilityID"), v.get("Severity", "UNKNOWN").upper(),
                     f"{v.get('PkgName')} {v.get('InstalledVersion')} - {v.get('Title', '')}"[:160],
                     res.get("Target", ""), fixed_version=v.get("FixedVersion") or "")


def parse_trivy_fs(data):
    return _parse_trivy("trivy-fs", data)


def parse_trivy_image(data):
    return _parse_trivy("trivy-image", data)


def parse_zap(data):
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances") or [{}]
            yield _f("zap", a.get("pluginid"), risk.get(str(a.get("riskcode")), "INFO"),
                     a.get("alert") or a.get("name", ""),
                     f"{inst[0].get('method', '')} {inst[0].get('uri', '')} (x{a.get('count', len(inst))})")


def parse_checkov(data):
    blocks = data if isinstance(data, list) else [data]
    for b in blocks:
        for c in b.get("results", {}).get("failed_checks", []):
            yield _f("checkov", c.get("check_id"), (c.get("severity") or "MEDIUM").upper(),
                     c.get("check_name", ""), f"{c.get('file_path')}:{c.get('file_line_range', [''])[0]}")


def parse_sonarqube(data):
    if data.get("status") not in ("OK", None):
        yield _f("sonarqube", "quality-gate", "HIGH",
                 f"Quality Gate SonarQube : {data.get('status')}", "SonarQube")


PARSERS = {"gitleaks": parse_gitleaks, "semgrep": parse_semgrep, "bandit": parse_bandit,
           "trivy-fs": parse_trivy_fs, "trivy-image": parse_trivy_image, "zap": parse_zap,
           "checkov": parse_checkov, "sonarqube": parse_sonarqube}


# ---------------------------------------------------------------- policy
def load_yaml(path):
    p = Path(path)
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}


def valid_exemptions(raw, today):
    """Return (active, problems). An exemption without owner/justification/expiry is refused."""
    active, problems = [], []
    for e in (raw or {}).get("exemptions", []) or []:
        missing = [k for k in ("id", "tool", "rule", "justification", "approved_by", "expires") if not e.get(k)]
        if missing:
            problems.append(f"Derogation {e.get('id', '?')} refusee : champs manquants {missing}")
            continue
        expires = e["expires"] if isinstance(e["expires"], dt.date) else dt.date.fromisoformat(str(e["expires"]))
        if expires < today:
            problems.append(f"Derogation {e['id']} EXPIREE le {expires} : le resultat redevient bloquant")
            continue
        active.append(e)
    return active, problems


def decide(f, rules, exemptions):
    for e in exemptions:
        if e["tool"] == f["tool"] and str(e["rule"]) == f["rule"] and e.get("location", "") in f["location"]:
            f["exemption"] = e["id"]
            return "EXEMPTED"
    if f["severity"] in rules.get("block", []):
        if rules.get("block_only_if_fix_available") and not f.get("fixed_version"):
            return "WARN"
        min_conf = rules.get("min_confidence_to_block")
        if min_conf and ["LOW", "MEDIUM", "HIGH"].index(f.get("confidence", "LOW")) < ["LOW", "MEDIUM", "HIGH"].index(min_conf):
            return "WARN"
        return "BLOCK"
    return "WARN"


def evaluate(reports_dir, policy, exemptions_raw, tools):
    today = dt.date.today()
    exemptions, problems = valid_exemptions(exemptions_raw, today)
    findings, per_tool = [], {}
    for tool in tools:
        rules = policy["tools"].get(tool, {})
        path = Path(reports_dir) / REPORT_FILES[tool]
        stat = {"report": path.name, "present": path.exists(), "BLOCK": 0, "WARN": 0, "EXEMPTED": 0}
        per_tool[tool] = stat
        if not path.exists():
            if tool in policy.get("required_reports", []):
                problems.append(f"Rapport manquant pour {tool} ({path.name}) : absence = echec")
                stat["BLOCK"] += 1
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "null")
        except json.JSONDecodeError as exc:
            problems.append(f"Rapport illisible pour {tool} : {exc}")
            stat["BLOCK"] += 1
            continue
        for f in PARSERS[tool](data):
            f["decision"] = decide(f, rules, exemptions)
            stat[f["decision"]] += 1
            findings.append(f)
    blocked = any(s["BLOCK"] for s in per_tool.values())
    return {"verdict": "BLOCK" if blocked else "PASS", "per_tool": per_tool,
            "findings": findings, "problems": problems}


# ---------------------------------------------------------------- outputs
def print_console(result):
    for tool, s in result["per_tool"].items():
        state = "absent" if not s["present"] else f"bloquants={s['BLOCK']} avertissements={s['WARN']} derogations={s['EXEMPTED']}"
        print(f"  [{'X' if s['BLOCK'] else 'OK'}] {tool:<12} {state}")
    for f in result["findings"]:
        if f["decision"] == "BLOCK":
            print(f"      BLOQUANT {f['severity']:<8} {f['rule']:<28} {f['location']}  {f['title'][:90]}")
    for p in result["problems"]:
        print(f"  ! {p}")
    print(f"\n  VERDICT : {result['verdict']}")


def append_history(path, result):
    if not path:
        return []
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    entry = {"build": os.environ.get("BUILD_NUMBER", "local"),
             "date": dt.datetime.now().isoformat(timespec="seconds"),
             "commit": os.environ.get("GIT_COMMIT", "")[:8],
             "verdict": result["verdict"],
             "block": sum(s["BLOCK"] for s in result["per_tool"].values()),
             "warn": sum(s["WARN"] for s in result["per_tool"].values()),
             "exempted": sum(s["EXEMPTED"] for s in result["per_tool"].values())}
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()][-20:]


def trend_svg(history):
    if len(history) < 1:
        return "<p>Pas encore d'historique.</p>"
    w, h, pad = 640, 200, 30
    top = max(1, max(max(e["block"], e["warn"]) for e in history))
    step = (w - 2 * pad) / max(1, len(history) - 1)

    def pts(key):
        return " ".join(f"{pad + i * step:.0f},{h - pad - (e[key] / top) * (h - 2 * pad):.0f}" for i, e in enumerate(history))

    labels = "".join(f'<text x="{pad + i * step:.0f}" y="{h - 8}" font-size="10" text-anchor="middle">#{e["build"]}</text>'
                     for i, e in enumerate(history))
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" style="max-width:{w}px;background:#fff;border:1px solid #ddd">'
            f'<polyline fill="none" stroke="#c0392b" stroke-width="2" points="{pts("block")}"/>'
            f'<polyline fill="none" stroke="#e67e22" stroke-width="2" stroke-dasharray="4" points="{pts("warn")}"/>'
            f'<text x="{pad}" y="16" font-size="11" fill="#c0392b">bloquants</text>'
            f'<text x="{pad + 80}" y="16" font-size="11" fill="#e67e22">avertissements (max {top})</text>{labels}</svg>')


def write_reports(out_dir, result, history):
    out = Path(out_dir)
    (out / "security-gate.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"Verdict du quality gate : {result['verdict']}", ""]
    for tool, s in result["per_tool"].items():
        lines.append(f"- {tool}: {s['BLOCK']} bloquant(s), {s['WARN']} avertissement(s), {s['EXEMPTED']} derogation(s)")
    lines += ["", "Resultats bloquants :"]
    lines += [f"  * [{f['tool']}] {f['severity']} {f['rule']} - {f['location']}" for f in result["findings"] if f["decision"] == "BLOCK"] or ["  (aucun)"]
    lines += [f"  ! {p}" for p in result["problems"]]
    (out / "gate-summary.txt").write_text("\n".join(lines), encoding="utf-8")

    color = {"BLOCK": "#c0392b", "WARN": "#e67e22", "EXEMPTED": "#2980b9"}
    rows_tools = "".join(
        f"<tr><td>{t}</td><td>{'oui' if s['present'] else 'NON'}</td><td style='color:#c0392b'><b>{s['BLOCK']}</b></td>"
        f"<td>{s['WARN']}</td><td>{s['EXEMPTED']}</td></tr>" for t, s in result["per_tool"].items())
    order = {"BLOCK": 0, "EXEMPTED": 1, "WARN": 2}
    rows = "".join(
        f"<tr><td style='color:{color[f['decision']]}'><b>{f['decision']}</b></td><td>{f['tool']}</td>"
        f"<td>{f['severity']}</td><td>{html.escape(f['rule'])}</td><td>{html.escape(f['title'])}</td>"
        f"<td>{html.escape(f['location'])}</td><td>{html.escape(f.get('exemption', '') or f.get('fixed_version', ''))}</td></tr>"
        for f in sorted(result["findings"], key=lambda x: (order[x["decision"]], SEVERITIES.index(x["severity"]) if x["severity"] in SEVERITIES else 9)))
    problems = "".join(f"<li>{html.escape(p)}</li>" for p in result["problems"])
    vcol = "#c0392b" if result["verdict"] == "BLOCK" else "#27ae60"
    page = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Quality gate securite</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}}table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}}
td,th{{border:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}th{{background:#f4f4f4}}
.v{{display:inline-block;padding:8px 18px;color:#fff;background:{vcol};font-size:22px;border-radius:6px}}</style></head><body>
<h1>Quality gate de securite - build #{html.escape(os.environ.get('BUILD_NUMBER', 'local'))}</h1>
<p class="v">{result['verdict']}</p>
<p>Job : {html.escape(os.environ.get('JOB_NAME', 'local'))} - commit {html.escape(os.environ.get('GIT_COMMIT', '')[:8])} - {dt.datetime.now():%Y-%m-%d %H:%M}</p>
<h2>Synthese par controle</h2><table><tr><th>Outil</th><th>Rapport</th><th>Bloquants</th><th>Avertissements</th><th>Derogations</th></tr>{rows_tools}</table>
{'<h2>Anomalies du processus</h2><ul>' + problems + '</ul>' if problems else ''}
<h2>Tendance (20 derniers builds)</h2>{trend_svg(history)}
<h2>Detail des resultats ({len(result['findings'])})</h2>
<table><tr><th>Decision</th><th>Outil</th><th>Severite</th><th>Regle / CVE</th><th>Description</th><th>Emplacement</th><th>Derogation / version corrigee</th></tr>{rows}</table>
</body></html>"""
    (out / "security-gate.html").write_text(page, encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["check", "evaluate"])
    ap.add_argument("--tool", choices=list(REPORT_FILES))
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--policy", default="security/policy.yml")
    ap.add_argument("--exemptions", default="security/exemptions.yml")
    ap.add_argument("--history", default=os.environ.get("HISTORY_FILE"))
    args = ap.parse_args(argv)

    policy = load_yaml(args.policy)
    exemptions = load_yaml(args.exemptions)
    if args.command == "check":
        if not args.tool:
            ap.error("check requiert --tool")
        result = evaluate(args.reports, policy, exemptions, [args.tool])
        print(f"== Gate {args.tool} ==")
        print_console(result)
        return 1 if result["verdict"] == "BLOCK" else 0

    result = evaluate(args.reports, policy, exemptions, list(REPORT_FILES))
    print("== Quality gate global ==")
    print_console(result)
    history = append_history(args.history, result)
    write_reports(args.reports, result, history)
    return 1 if result["verdict"] == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())
