"""Build the static GitHub Pages site into ``_site/``.

Contents: a landing page (numbers read from ``docs/meta_validation.json``), and the committed sample
reports (``docs/sample_report/*.html``). Usage: ``uv run python scripts/build_site.py [out_dir]``.
"""

from __future__ import annotations

import html
import json
import shutil
import sys
from pathlib import Path

REPO = "https://github.com/PiyushDas-2004/agentguard"
ROOT = Path(__file__).resolve().parent.parent

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGuard</title>
<meta name="description" content="Security and quality evaluation framework for AI agents: canary-based red-teaming, statistically rigorous scoring, self-validating detectors.">
<style>
:root{{--bg:#f7f8fa;--panel:#fff;--ink:#1d2330;--muted:#5d6678;--line:#e2e6ee;--accent:#3355cc;--ok:#1e8a4c;--bad:#c62828;--code:#f1f3f7}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1218;--panel:#171b24;--ink:#e6e9ef;--muted:#9aa3b5;--line:#2a3140;--accent:#7d9bff;--ok:#5ad08a;--bad:#ff6b6b;--code:#10141b}}}}
*{{box-sizing:border-box}}body{{margin:0;font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink)}}
main{{max-width:980px;margin:0 auto;padding:32px 16px 64px}}h1{{font-size:34px;margin:0 0 8px}}h2{{font-size:21px;margin:36px 0 12px}}
.lead{{font-size:18px;color:var(--muted);margin:0 0 20px}}a{{color:var(--accent)}}
.btns{{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0}}.btn{{display:inline-block;padding:9px 16px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--ink);text-decoration:none;font-weight:600}}
.btn.primary{{background:var(--accent);border-color:var(--accent);color:#fff}}
.grid{{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(160px,1fr))}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}}
.v{{font-size:26px;font-weight:700}}.l{{color:var(--muted);font-size:13px}}
table{{border-collapse:collapse;width:100%;font-size:15px;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line)}}th{{font-size:12px;text-transform:uppercase;color:var(--muted)}}
.F,.D{{color:var(--bad);font-weight:700}}.A,.B{{color:var(--ok);font-weight:700}}.C{{font-weight:700}}
pre{{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;font-size:14px}}
ul{{padding-left:20px}}footer{{margin-top:40px;color:var(--muted);font-size:14px}}
</style>
</head>
<body><main>
<h1>🛡 AgentGuard</h1>
<p class="lead">Red-team and evaluate any AI agent — LLM app, RAG pipeline, tool-using agent or MCP server — for security
<em>and</em> quality, with deterministic canary-based detection, Wilson confidence intervals, and self-validating accuracy.</p>
<div class="btns">
  <a class="btn primary" href="reports/vulnerable.html">Sample report: vulnerable agent</a>
  <a class="btn" href="reports/hardened.html">Sample report: hardened agent</a>
  <a class="btn" href="{repo}">Source on GitHub</a>
  <a class="btn" href="https://render.com/deploy?repo={repo}">Deploy the live dashboard</a>
</div>

<h2>AgentGuard grading itself</h2>
<p>The full security suite runs against five demo agents whose vulnerabilities are documented in
<a href="{repo}/blob/main/examples/ground_truth.yaml">ground truth</a>. All use the same naive model;
only their defense code differs.</p>
<div class="grid">{metric_cards}</div>
<h2>Demo agents</h2>
<table><tr><th>Agent</th><th>Risk score</th><th>Grade</th><th>Over-refusal</th></tr>{agent_rows}</table>

<h2>Try it in 60 seconds</h2>
<pre>git clone {repo} && cd agentguard
uv sync
uv run agentguard run -c examples/demo.yaml --offline</pre>
<p>Or run the dashboard, pre-seeded with demo runs:</p>
<pre>docker run -p 8000:8000 ghcr.io/piyushdas-2004/agentguard-demo:latest</pre>

<h2>What it covers</h2>
<ul>
<li>12 attack categories (prompt injection direct and indirect, jailbreaks, system-prompt leakage, exfiltration, PII, excessive agency,
insecure output, memory and RAG poisoning, denial of wallet, package hallucination) plus an over-refusal benign set.</li>
<li>Instrumented tool sandbox with a policy engine and default-deny approval gate: agency is judged from actions, not words.</li>
<li>Canary tokens detected in 13 encodings; nine deterministic detectors with evidence spans; rubric-driven LLM judge.</li>
<li>Quality metrics (tool trajectories, task success, consistency, RAG faithfulness/relevancy/precision/recall).</li>
<li>Reports in HTML, JSON, SARIF 2.1.0, JUnit and Markdown; GitHub Action; risk thresholds that fail CI.</li>
</ul>
<p>Docs: <a href="{repo}#readme">README</a> · <a href="{repo}/blob/main/docs/ARCHITECTURE.md">Architecture</a> ·
<a href="{repo}/blob/main/docs/SCORING.md">Scoring</a> · <a href="{repo}/blob/main/docs/VALIDATION.md">Validation</a> ·
<a href="{repo}/blob/main/docs/THREAT_MODEL.md">Threat model</a> · <a href="{repo}/blob/main/RESPONSIBLE_USE.md">Responsible use</a></p>
<footer>Apache-2.0 · AgentGuard is a defensive tool: all bundled attacks use canary tokens and mock tools.</footer>
</main></body></html>
"""


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "_site"
    if out.exists():
        shutil.rmtree(out)
    (out / "reports").mkdir(parents=True)
    meta = json.loads((ROOT / "docs" / "meta_validation.json").read_text(encoding="utf-8"))
    overall = meta["overall"]
    pairs = overall["tp"] + overall["fp"] + overall["tn"] + overall["fn"]
    cards = [
        (f"{overall['precision']:.3f}", "precision"),
        (f"{overall['recall']:.3f}", "recall (target ≥ 0.90)"),
        (f"{overall['f1']:.3f}", "F1"),
        (f"{overall['fpr']:.3f}", "false-positive rate (target ≤ 0.10)"),
        (str(pairs), "agent × category pairs checked"),
    ]
    metric_cards = "".join(
        f'<div class="card"><div class="v">{html.escape(v)}</div><div class="l">{html.escape(label)}</div></div>'
        for v, label in cards
    )
    agent_rows = "".join(
        f"<tr><td><code>{html.escape(name)}</code></td><td>{info['risk']:.1f}</td>"
        f'<td class="{html.escape(str(info["grade"]))}">{html.escape(str(info["grade"]))}</td>'
        f"<td>{float(info['over_refusal_rate']):.1%}</td></tr>"
        for name, info in meta["risk_scores"].items()
    )
    (out / "index.html").write_text(
        PAGE.format(repo=REPO, metric_cards=metric_cards, agent_rows=agent_rows), encoding="utf-8"
    )
    samples = ROOT / "docs" / "sample_report"
    shutil.copyfile(samples / "index.html", out / "reports" / "vulnerable.html")
    shutil.copyfile(samples / "hardened.html", out / "reports" / "hardened.html")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    print(f"site written to {out} ({sum(f.stat().st_size for f in out.rglob('*') if f.is_file()) // 1024} KiB)")


if __name__ == "__main__":
    main()
