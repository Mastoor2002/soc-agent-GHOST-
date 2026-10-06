"""
STEP 8 — Benchmark: run GHOST on EVERY scenario and build one results table.

WHY: One good demo can be luck. A table across several attacks — including what
GHOST missed and the legitimate activity it should NOT call an attack — is what
convinces judges (and is how real detection teams evaluate their tools).

Two layers are measured separately:
  detection  — did any alert's rule tags cover the answer-key technique?
  agent      — did the AI confirm it (true_positive) with that technique, after the
               grounding check? Did it dismiss the known-legitimate activity?

Run:
    python -m src.benchmark                 # detection only (instant, no API key)
    python -m src.benchmark --agent mock    # + scripted agent
    python -m src.benchmark --agent nim     # + real Nemotron (a few minutes per scenario)
Writes reports/benchmark.md (paste it into your writeup) and reports/benchmark.json.
"""
import argparse
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv

from . import detect, scenarios
from .agent import MockModel, NIMModel, investigate
from .tools import Toolbox

ROOT = Path(__file__).resolve().parent.parent


def run_scenario(name: str, agent: str | None) -> dict:
    ctx, truth = scenarios.load_context(name), scenarios.load_truth(name)
    t0 = time.perf_counter()
    df = detect.load_logs(scenarios.path(name) / "logs.jsonl")
    alerts = detect.run_all(df)
    detect_s = time.perf_counter() - t0

    tagged = {t for a in alerts for t in a.get("rule_tags", [])}
    expected, det_hit = scenarios.technique_recall(truth, tagged)
    row = {"scenario": name, "title": ctx.get("title", name), "events": len(df),
           "detect_seconds": round(detect_s, 3), "alerts": len(alerts),
           "expected": sorted(expected), "detection_hit": sorted(det_hit)}

    reports = {}
    if agent:
        toolbox, prior = Toolbox(df, ctx), []
        t0 = time.perf_counter()
        for a in alerts:
            model = MockModel() if agent == "mock" else NIMModel()
            r = investigate(a, toolbox, model, prior=prior, verbose=False)
            for t in r.get("trace", []):
                t.pop("result_full", None)
            if agent == "nim":  # record who produced it, shown by the online demo
                from .agent import provider
                r["model"], r["provider"] = os.environ.get("NIM_MODEL"), provider()[0]
                r["run_date"] = time.strftime("%Y-%m-%d")
            prior.append(r)
            reports[a["id"]] = r
        found = {t for r in prior if r.get("verdict") == "true_positive" for t in r.get("mitre", [])}
        _, agent_hit = scenarios.technique_recall(truth, found)
        row.update({"agent_seconds": round(time.perf_counter() - t0, 1),
                    "agent_hit": sorted(agent_hit),
                    "confirmed": sum(r.get("verdict") == "true_positive" for r in prior),
                    "unverified": sorted({t for r in prior for t in r.get("unverified_mitre", [])}),
                    "self_corrected": sum(bool(r.get("self_corrected")) for r in prior)})
        (ROOT / "reports").mkdir(exist_ok=True)
        (ROOT / "reports" / f"incidents_{name}.json").write_text(json.dumps(prior, indent=2))
    row["benign"] = scenarios.benign_results(truth, alerts, reports)
    return row


def markdown(rows: list[dict], agent: str | None) -> str:
    head = "| Scenario | Events | Alerts | Answer key | Detection | "
    head += ("Agent | Confirmed | Legit activity dismissed | Agent time |" if agent else "Legit activity flagged |")
    lines = [head, "|" + "---|" * (head.count("|") - 1)]
    for r in rows:
        key = ", ".join(r["expected"])
        det = f"{len(r['detection_hit'])}/{len(r['expected'])}"
        cells = [r["title"], f"{r['events']:,}", str(r["alerts"]), key, det]
        if agent:
            ben = r["benign"]
            cells += [f"{len(r['agent_hit'])}/{len(r['expected'])}", f"{r['confirmed']}/{r['alerts']}",
                      (f"{sum(b['correct'] for b in ben)}/{len(ben)}" if ben else "—"),
                      f"{r['agent_seconds']:.0f}s"]
        else:
            cells += [str(len(r["benign"])) if r["benign"] else "—"]
        lines.append("| " + " | ".join(cells) + " |")
    tot_e = sum(len(r["expected"]) for r in rows)
    lines.append("")
    lines.append(f"**Detection coverage:** {sum(len(r['detection_hit']) for r in rows)}/{tot_e} "
                 f"answer-key techniques across {len(rows)} scenarios, "
                 f"{sum(r['events'] for r in rows):,} events.")
    if agent:
        lines.append(f"**Agent coverage ({agent}):** {sum(len(r['agent_hit']) for r in rows)}/{tot_e}. "
                     f"Hallucinated techniques rejected by grounding check: "
                     f"{sum(len(r['unverified']) for r in rows)}. "
                     f"Reports fixed by self-correction: {sum(r['self_corrected'] for r in rows)}.")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--agent", choices=["mock", "nim"])
    p.add_argument("--model", help="override NIM_MODEL")
    args = p.parse_args()
    load_dotenv(ROOT / ".env")
    if args.model:
        os.environ["NIM_MODEL"] = args.model
    rows = []
    for name in scenarios.list_scenarios():
        print(f"Running {name} ...", flush=True)
        rows.append(run_scenario(name, args.agent))
    md = markdown(rows, args.agent)
    if args.agent == "nim":
        from .agent import provider
        md += f"\n\nModel: `{os.environ.get('NIM_MODEL')}` via {provider()[0]}"
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "benchmark.md").write_text(md + "\n")
    (ROOT / "reports" / "benchmark.json").write_text(json.dumps(rows, indent=2))
    print("\n" + md + "\n\nSaved reports/benchmark.md and reports/benchmark.json")


if __name__ == "__main__":
    main()
