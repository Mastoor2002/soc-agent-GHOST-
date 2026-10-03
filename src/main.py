"""
STEP 6 — Run the whole pipeline end to end.

    logs -> detection -> agent investigation -> reports -> score vs answer key

Run:
    python -m src.main --mock          # no API key needed
    python -m src.main                 # real Nemotron via NIM (needs .env)
    python -m cudf.pandas -m src.main  # same, with detection on an NVIDIA GPU
"""
import argparse
import json
import time
from pathlib import Path

from dotenv import load_dotenv

from . import detect
from .agent import MockModel, NIMModel, investigate
from .tools import Toolbox

ROOT = Path(__file__).resolve().parent.parent


def score(reports: list[dict]) -> None:
    """Compare results to ground_truth.json. Numbers like these win hackathons."""
    truth = json.loads((ROOT / "data" / "ground_truth.json").read_text())
    expected = {t for s in truth for t in s["mitre"]}
    found = {t for r in reports if r.get("verdict") == "true_positive" for t in r.get("mitre", [])}
    print("\n=== Scorecard ===")
    print(f"Attack stages planted:     {len(truth)}")
    print(f"Alerts confirmed:          {sum(r.get('verdict') == 'true_positive' for r in reports)}")
    print(f"MITRE techniques expected: {sorted(expected)}")
    print(f"MITRE techniques found:    {sorted(found)}")
    print(f"Technique recall:          {len(found & expected)}/{len(expected)}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mock", action="store_true", help="use scripted model, no API key")
    args = p.parse_args()
    load_dotenv(ROOT / ".env")

    t0 = time.perf_counter()
    df = detect.load_logs()
    alerts = detect.run_all(df)
    print(f"Detection: scanned {len(df):,} events in {time.perf_counter() - t0:.2f}s "
          f"-> {len(alerts)} alerts\n")

    toolbox = Toolbox(df)
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
    (out / "incidents.json").write_text(json.dumps(reports, indent=2))
    print(f"Saved {len(reports)} reports -> reports/incidents.json")
    score(reports)


if __name__ == "__main__":
    main()
