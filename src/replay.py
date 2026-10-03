"""
STEP 2 — Replay logs as if they were arriving live.

WHY: A real SOC doesn't get a finished file — events stream in second by second.
For your demo, "watching the attack happen live" is far more impressive than
loading a CSV. This module turns the log file into a stream.

`stream_logs()` is a *generator* (it uses `yield`). Instead of returning all
events at once, it hands them out one at a time, and the caller processes each
as it arrives. Same idea as reading from Kafka or a syslog socket in production.

Run:  python -m src.replay --speed 600     (600x faster than real time)
"""
import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Iterator

LOG_FILE = Path(__file__).resolve().parent.parent / "data" / "logs.jsonl"


def stream_logs(path: Path = LOG_FILE, speed: float = 0) -> Iterator[dict]:
    """Yield log events in order. speed=0 means as fast as possible;
    speed=600 means one real minute of logs plays in 0.1 seconds."""
    prev = None
    with open(path) as f:
        for line in f:
            event = json.loads(line)
            if speed > 0:
                now = datetime.fromisoformat(event["timestamp"])
                if prev is not None:
                    gap = (now - prev).total_seconds() / speed
                    time.sleep(min(gap, 2))  # never stall the demo more than 2s
                prev = now
            yield event


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--speed", type=float, default=600)
    p.add_argument("--limit", type=int, default=40)
    args = p.parse_args()
    for i, e in enumerate(stream_logs(speed=args.speed)):
        if i >= args.limit:
            break
        who = e.get("user", e.get("host"))
        print(f"{e['timestamp']}  {e['source']:<8} {e['event']:<10} {who:<10} "
              f"{e.get('outcome', e.get('action', ''))}")
