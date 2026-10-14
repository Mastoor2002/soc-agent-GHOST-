"""
STEP 11 — Bring your own logs: turn an uploaded file into a GHOST scenario.

WHY: Judges and users shouldn't be limited to our five recordings. This accepts
two kinds of file and produces the same table the detectors and agent already use:

  1. GHOST format: one JSON event per line with "timestamp" and "source"
     (exactly what data/<scenario>/logs.jsonl contains), as .jsonl/.json or .csv.
  2. Raw Windows event logs as flattened JSON lines, the way OTRF Security Datasets,
     Winlogbeat/Elastic and many SIEM exports store them: fields like "EventID",
     "Channel", "Hostname", "@timestamp". These go through the same normalizer that
     built our real scenarios (load_otrf.normalize).

An upload has no answer key and no company context (network ranges, staff
directory), so the agent is told that plainly instead of being given guesses.
"""
import io
import ipaddress
import json
from datetime import datetime

import pandas as pd

from . import detect
from .load_otrf import dedupe_processes, normalize

MAX_BYTES = 50 * 1024 * 1024
MAX_EVENTS = 300_000


class UploadError(ValueError):
    """A problem the person uploading can fix; the message is shown to them."""


def _records(name: str, data: bytes) -> list[dict]:
    if len(data) > MAX_BYTES:
        raise UploadError(f"File is {len(data) / 1e6:.0f} MB; the limit is {MAX_BYTES // 2**20} MB.")
    text = data.decode("utf-8-sig", errors="replace")
    if name.lower().endswith(".csv"):
        try:
            return pd.read_csv(io.StringIO(text), dtype=str, nrows=MAX_EVENTS + 1).to_dict("records")
        except Exception as e:
            raise UploadError(f"Couldn't read the CSV: {e}")
    stripped = text.lstrip()
    if stripped.startswith("["):  # one JSON array instead of one object per line
        try:
            rows = json.loads(stripped)
        except ValueError as e:
            raise UploadError(f"Couldn't read the JSON array: {e}")
    else:
        rows, bad = [], 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                bad += 1
            if len(rows) > MAX_EVENTS:
                break
        if bad and not rows:
            raise UploadError("No line could be read as JSON. Expected one JSON event per line.")
    rows = [r for r in rows if isinstance(r, dict)]
    if not rows:
        raise UploadError("The file has no events.")
    if len(rows) > MAX_EVENTS:
        raise UploadError(f"More than {MAX_EVENTS:,} events; please upload a smaller slice.")
    return rows


def _dedupe_services(events: list[dict]) -> list[dict]:
    """7045 and 4697 describe the same service install: keep one (as load_otrf does)."""
    seen, keep = [], []
    for e in events:
        if e["source"] == "service":
            t = datetime.fromisoformat(e["timestamp"])
            if any(h == e["host"] and n == e.get("service_name") and abs((t - t0).total_seconds()) <= 5
                   for h, n, t0 in seen):
                continue
            seen.append((e["host"], e.get("service_name"), t))
        keep.append(e)
    return keep


def to_events(name: str, data: bytes) -> tuple[pd.DataFrame, str]:
    """Parse an upload into GHOST's event table. Returns (events, detected format)."""
    rows = _records(name, data)
    sample = rows[:50]
    if all("timestamp" in r and "source" in r for r in sample):
        fmt, events = "GHOST format", rows
    elif sum("EventID" in r for r in sample) >= len(sample) // 2:
        fmt = "raw Windows event logs"
        events = []
        for r in rows:
            if "EventID" not in r or not (r.get("@timestamp") or r.get("UtcTime")):
                continue
            try:
                r["EventID"] = int(r["EventID"])
            except (TypeError, ValueError):
                pass
            try:
                n = normalize(r)
            except Exception:  # one odd event shouldn't sink the whole upload
                n = None
            if n:
                events.append(n)
        events = _dedupe_services(dedupe_processes(sorted(events, key=lambda e: e["timestamp"])))
    else:
        keys = ", ".join(sorted(sample[0])[:8])
        raise UploadError("Unrecognized format. Expected GHOST events (fields \"timestamp\" and "
                          "\"source\") or raw Windows events (\"EventID\", \"Channel\", "
                          f"\"@timestamp\"). Your first event has: {keys}")
    if not events:
        raise UploadError("No usable events after reading the file.")
    df = pd.DataFrame(events)
    for c in detect.COLUMNS:
        if c not in df:
            df[c] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"])
    df["timestamp"] = df["timestamp"].dt.tz_localize(None)
    for c in ("dst_port", "bytes_out"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    if df.empty:
        raise UploadError("No event had a readable timestamp.")
    return df.sort_values("timestamp").reset_index(drop=True), fmt


def parse_ranges(text: str) -> list[str]:
    """'10.0.0.0/8, 192.168.1.0/24' -> validated list; raises UploadError on a typo."""
    out = []
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            raise UploadError(f"'{part}' is not a network range like 10.0.0.0/8")
    return out


def context(name: str, n_events: int, fmt: str, ranges: list[str]) -> dict:
    """What the agent knows about an upload: honestly, very little."""
    return {
        "title": f"Your upload: {name}",
        "description": f"{n_events:,} events read as {fmt}. No answer key: GHOST's verdicts "
                       "are its own, so check them against what you know happened.",
        "known_subnets": ranges,
        "network_info": bool(ranges),
        "threat_intel": {},
        "users": {},
        "directory_note": "Uploaded logs come with no employee directory. Judge what is normal "
                          "for an account from its own activity in the logs.",
        "chart_note": "Your uploaded events over time.",
    }
