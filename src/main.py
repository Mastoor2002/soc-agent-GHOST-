"""
STEP 6 — Run the whole pipeline end to end.

    logs -> detection -> agent investigation -> reports -> score vs answer key

Run:
    python -m src.main --mock                         # practice scenario, no API key
    python -m src.main                                # practice scenario, Nemotron (needs .env)
    python -m src.main --scenario real_psexec         # real recorded attack, Nemotron
    python -m cudf.pandas -m src.main                 # same, with detection on an NVIDIA GPU
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


def score(reports: list[dict], scenario: str, alerts: list[dict]) -> None:
    """Compare results to the scenario's answer key. Numbers like these win hackathons."""
    truth = scenarios.load_truth(scenario)
    found = {t for r in reports if r.get("verdict") == "true_positive" for t in r.get("mitre", [])}
    expected, hit = scenarios.technique_recall(truth, found)
    print("\n=== Scorecard ===")
    print(f"Attack stages in answer key: {len(truth)}")
    print(f"Alerts confirmed:            {sum(r.get('verdict') == 'true_positive' for r in reports)}")
    print(f"MITRE techniques expected:   {sorted(expected)}")
    print(f"MITRE techniques found:      {sorted(found)}")
    print(f"Technique recall:            {len(hit)}/{len(expected)}")
    unverified = sorted({t for r in reports for t in r.get("unverified_mitre", [])})
    if unverified:
        print(f"Rejected by grounding check: {unverified}  (claimed without evidence)")
    for b in scenarios.benign_results(truth, alerts, {r["alert_id"]: r for r in reports}):
        mark = "OK " if b["correct"] else "MISS"
        print(f"Legit activity [{mark}]:        {b['alert_id']} -> {b['verdict']}  ({b['note'][:70]}...)")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mock", action="store_true", help="use scripted model, no API key")
    p.add_argument("--scenario", default=scenarios.DEFAULT, choices=scenarios.list_scenarios())
    p.add_argument("--model", help="override NIM_MODEL from .env, e.g. to compare models")
    args = p.parse_args()
    load_dotenv(ROOT / ".env")
    if args.model:
        os.environ["NIM_MODEL"] = args.model
    if not args.mock:
        print(f"Model: {os.environ.get('NIM_MODEL')}")
    print(f"Scenario: {scenarios.load_context(args.scenario).get('title', args.scenario)}")

    t0 = time.perf_counter()
    df = detect.load_logs(scenarios.path(args.scenario) / "logs.jsonl")
    alerts = detect.run_all(df)
    print(f"Detection: scanned {len(df):,} events in {time.perf_counter() - t0:.2f}s "
          f"-> {len(alerts)} alerts\n")

    toolbox = Toolbox(df, scenarios.load_context(args.scenario))
    reports = []
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['id']}: {alert['summary']}")
        model = MockModel() if args.mock else NIMModel()
        t = time.perf_counter()
        report = investigate(alert, toolbox, model, prior=reports)
        report["seconds"] = round(time.perf_counter() - t, 1)
        reports.append(report)
        print(f"  -> {report.get('verdict')} ({report.get('confidence', '?')}%): "
              f"{report.get('title', '')}  [{report['seconds']}s]\n")

    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    for r in reports:
        r["model"] = "mock" if args.mock else os.environ.get("NIM_MODEL")
        for t in r.get("trace", []):
            t.pop("result_full", None)
    (out / f"incidents_{args.scenario}.json").write_text(json.dumps(reports, indent=2))
    print(f"Saved {len(reports)} reports -> reports/incidents_{args.scenario}.json")
    score(reports, args.scenario, alerts)


if __name__ == "__main__":
    main()
