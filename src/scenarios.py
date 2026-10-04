"""
Scenarios — each folder in data/ is one self-contained test case.

    data/<scenario>/
        logs.jsonl          the security logs (one JSON event per line)
        ground_truth.json   the answer key — detectors and the agent never read it
        context.json        what a real SOC would already know: company IP ranges,
                            employee directory, threat-intel feed, a description

WHY: This lets GHOST run the same pipeline on our practice attack AND on real
recorded attacks, and score itself on each. Adding a new test case = adding a folder.
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT = "synthetic"


def list_scenarios() -> list[str]:
    """Every folder in data/ that has a logs.jsonl file."""
    names = sorted(p.parent.name for p in DATA_DIR.glob("*/logs.jsonl"))
    # Put the default first so it's the dashboard's starting choice
    return sorted(names, key=lambda n: n != DEFAULT)


def path(name: str) -> Path:
    return DATA_DIR / name


def load_context(name: str) -> dict:
    f = path(name) / "context.json"
    return json.loads(f.read_text()) if f.exists() else {}


def load_truth(name: str) -> list[dict]:
    f = path(name) / "ground_truth.json"
    return json.loads(f.read_text()) if f.exists() else []


def technique_recall(truth: list[dict], found: set[str]) -> tuple[set, set]:
    """Which expected techniques were found. A sub-technique counts for its parent:
    finding T1021.002 (SMB/Admin Shares) satisfies an expected T1021 (Remote Services)."""
    expected = {t for stage in truth for t in stage.get("mitre", [])}
    hit = {e for e in expected if any(f == e or f.startswith(e + ".") for f in found)}
    return expected, hit


def benign_results(truth: list[dict], alerts: list[dict], reports: dict) -> list[dict]:
    """For each known-legitimate activity in the answer key: did a detector flag it,
    and if so, did the agent correctly dismiss it as a false positive?"""
    out = []
    for item in [t for t in truth if t.get("benign")]:
        m = item["match"]
        for a in alerts:
            if a["type"] == m["type"] and m["process"].lower() in str(a.get("process", "")).lower():
                verdict = reports.get(a["id"], {}).get("verdict")
                out.append({"alert_id": a["id"], "note": item["note"], "verdict": verdict,
                            "correct": verdict in ("false_positive", "needs_review")})
    return out
