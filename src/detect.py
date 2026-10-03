"""
STEP 3 — Detect suspicious activity (turn millions of logs into a few alerts).

WHY: An LLM can't read millions of log lines — it's too slow and expensive.
So a SOC works in two layers:
  1. Fast detection (this file): cheap rules and statistics scan EVERYTHING
     and raise a small number of alerts.
  2. Smart investigation (agent.py): the LLM digs into each alert like a
     human analyst would.

THE GPU PART: this file uses pandas. NVIDIA's RAPIDS library has `cudf.pandas`,
which runs the SAME pandas code on a GPU with zero code changes:

    python -m cudf.pandas -m src.main     # on a machine with an NVIDIA GPU

On millions of rows that's often 10–100x faster. Benchmarking CPU vs GPU on a
big log file is your "why we needed NVIDIA" slide for the judges.

Each detector returns alerts as plain dicts — the agent's starting point.
"""
import pandas as pd

from .replay import LOG_FILE


def load_logs(path=LOG_FILE) -> pd.DataFrame:
    df = pd.read_json(path, lines=True)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


def detect_brute_force(df: pd.DataFrame, threshold: int = 10, window: str = "10min") -> list[dict]:
    """Many failed logins from ONE IP in a short window, followed by a success.
    A few typos (1–3 failures) are normal; 30+ in minutes is a password-guessing tool."""
    alerts = []
    auth = df[(df.source == "auth") & (df.event == "login")]
    for ip, g in auth.groupby("src_ip"):
        fails = g[g.outcome == "failure"].set_index("timestamp")
        if len(fails) < threshold:
            continue
        # Rolling count: "how many failures in the last 10 minutes" at each event
        peak = fails["outcome"].rolling(window).count().max()
        if peak < threshold:
            continue
        last_fail = fails.index.max()
        success = g[(g.outcome == "success") & (g.timestamp >= last_fail)]
        alerts.append({
            "type": "brute_force",
            "severity": "high" if len(success) else "medium",
            "time": str(success.timestamp.min() if len(success) else last_fail),
            "src_ip": ip,
            "user": g.user.mode().iloc[0],
            "summary": f"{int(peak)} failed logins from {ip} within {window}"
                       + (" followed by a SUCCESSFUL login" if len(success) else ""),
        })
    return alerts


def detect_lateral_movement(df: pd.DataFrame, min_hosts: int = 3, window: str = "30min") -> list[dict]:
    """One account logging into many different machines quickly.
    Normal staff touch their own workstation plus a server or two per day."""
    alerts = []
    net = df[(df.source == "auth") & (df.outcome == "success") & (df.method == "network")]
    for user, g in net.groupby("user"):
        g = g.sort_values("timestamp")
        times, hosts = g.timestamp.tolist(), g.host.tolist()
        for i in range(len(times)):
            # Hosts visited within `window` starting at event i
            in_window = {h for t, h in zip(times[i:], hosts[i:])
                         if t - times[i] <= pd.Timedelta(window)}
            if len(in_window) >= min_hosts:
                alerts.append({
                    "type": "lateral_movement",
                    "severity": "high",
                    "time": str(times[i]),
                    "user": user,
                    "hosts": sorted(in_window),
                    "summary": f"{user} logged into {len(in_window)} hosts within {window}: "
                               f"{', '.join(sorted(in_window))}",
                })
                break  # one alert per user is enough
    return alerts


def detect_exfiltration(df: pd.DataFrame, mb_threshold: float = 500) -> list[dict]:
    """Large volumes of data leaving to an EXTERNAL address.
    Internal backups (10.x.x.x) are excluded — that's the false-positive trap."""
    fw = df[(df.source == "firewall") & ~df.dst_ip.astype(str).str.startswith("10.")]
    totals = fw.groupby(["host", "dst_ip"]).agg(
        mb=("bytes_out", lambda b: b.sum() / 1e6),
        first=("timestamp", "min"),
        conns=("bytes_out", "size"),
    ).reset_index()
    alerts = []
    for _, r in totals[totals.mb > mb_threshold].iterrows():
        alerts.append({
            "type": "exfiltration",
            "severity": "critical",
            "time": str(r["first"]),
            "host": r.host,
            "dst_ip": r.dst_ip,
            "summary": f"{r.host} sent {r.mb:,.0f} MB to external {r.dst_ip} "
                       f"over {r.conns} connections",
        })
    return alerts


def run_all(df: pd.DataFrame) -> list[dict]:
    alerts = detect_brute_force(df) + detect_lateral_movement(df) + detect_exfiltration(df)
    for i, a in enumerate(sorted(alerts, key=lambda a: a["time"]), 1):
        a["id"] = f"ALERT-{i:03d}"
    return sorted(alerts, key=lambda a: a["time"])


if __name__ == "__main__":
    df = load_logs()
    print(f"Scanned {len(df):,} events")
    for a in run_all(df):
        print(f"[{a['severity'].upper():8}] {a['id']} {a['type']}: {a['summary']}")
