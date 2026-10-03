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
Detectors for every scenario run on every dataset: a detector simply finds
nothing when its log type isn't present.
"""
import json

import pandas as pd

from .replay import LOG_FILE

# Every scenario gets these columns, even if its logs never fill some of them,
# so detectors and tools never crash on a missing column.
COLUMNS = ["timestamp", "source", "event", "outcome", "action", "user", "host",
           "src_ip", "dst_ip", "dst_port", "method", "bytes_out",
           "process", "parent_process", "command_line", "service_name"]


def load_logs(path=LOG_FILE) -> pd.DataFrame:
    with open(path) as f:
        df = pd.DataFrame([json.loads(line) for line in f])
    for c in COLUMNS:
        if c not in df:
            df[c] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    return df.sort_values("timestamp").reset_index(drop=True)


def _basename(path) -> str:
    """'C:\\Windows\\System32\\cmd.exe' -> 'cmd.exe'"""
    return str(path).replace("/", "\\").split("\\")[-1].lower()


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


# ---------------------------------------------------------------- Windows detectors
SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe",
          "wscript.exe", "cscript.exe")


def detect_remote_service_exec(df: pd.DataFrame, window_s: int = 120) -> list[dict]:
    """PsExec-style lateral movement: someone logs in OVER THE NETWORK to a machine,
    and a new Windows service appears there within seconds. Services that run a
    command shell are almost never legitimate software installs."""
    alerts = []
    services = df[df.source == "service"]
    logons = df[(df.source == "auth") & (df.outcome == "success") & (df.method == "network")]
    for _, svc in services.iterrows():
        near = logons[(logons.host == svc.host)
                      & ((logons.timestamp - svc.timestamp).abs().dt.total_seconds() <= window_s)
                      & ~logons.src_ip.isin(["::1", "127.0.0.1", "-"])]
        runs_shell = any(sh.split(".")[0] in str(svc.command_line).lower() for sh in SHELLS)
        if near.empty and not runs_shell:
            continue
        who = near.iloc[0] if len(near) else None
        alerts.append({
            "type": "remote_service_execution",
            "severity": "critical" if (len(near) and runs_shell) else "high",
            "time": str(svc.timestamp),
            "host": svc.host,
            "user": who.user if who is not None else svc.user,
            "src_ip": who.src_ip if who is not None else None,
            "service_name": svc.service_name,
            "summary": (f"New service '{svc.service_name}' on {svc.host} runs a command shell"
                        + (f", seconds after a network logon by {who.user} from {who.src_ip}"
                           if who is not None else "")),
        })
    return alerts


def detect_encoded_powershell(df: pd.DataFrame) -> list[dict]:
    """PowerShell started with -enc <base64>: the command is hidden on purpose.
    Rare in normal admin work, extremely common in attack tools. One alert per host."""
    procs = df[(df.source == "process")
               & df.process.astype(str).str.lower().str.endswith(("powershell.exe", "pwsh.exe"))
               & df.command_line.astype(str).str.contains(r"\s-e(?:nc|ncodedcommand|c)?\s",
                                                          case=False, regex=True)]
    alerts = []
    for host, g in procs.groupby("host"):
        first = g.iloc[0]
        alerts.append({
            "type": "encoded_powershell",
            "severity": "high",
            "time": str(first.timestamp),
            "host": host,
            "user": first.user,
            "parent_process": _basename(first.parent_process),
            "summary": f"PowerShell with a hidden (base64-encoded) command ran on {host} as "
                       f"{first.user}, launched by {_basename(first.parent_process)}",
        })
    return alerts


def detect_script_beacon(df: pd.DataFrame) -> list[dict]:
    """A command shell or script engine making a web connection. Browsers talk to
    the web; PowerShell running as SYSTEM usually shouldn't — it's a classic C2 callback."""
    net = df[(df.source == "network")
             & df.process.apply(_basename).isin(SHELLS)
             & df.dst_port.isin([80, 443, 8080, 8443])]
    alerts = []
    for (host, dst), g in net.groupby(["host", "dst_ip"]):
        first = g.iloc[0]
        alerts.append({
            "type": "script_c2_beacon",
            "severity": "high",
            "time": str(first.timestamp),
            "host": host,
            "user": first.user,
            "dst_ip": dst,
            "summary": f"{_basename(first.process)} on {host} (as {first.user}) connected to "
                       f"{dst}:{int(first.dst_port)} — {len(g)} connection(s)",
        })
    return alerts


# Like real detection rules (e.g. Sigma), each rule is tagged with the ATT&CK
# techniques it was written to catch. The agent treats these as HYPOTHESES:
# it must confirm them with evidence, drop the wrong ones, and add what it finds.
RULE_TAGS = {'brute_force': ['T1110'],
             'lateral_movement': ['T1021'],
             'exfiltration': ['T1048'],
             'remote_service_execution': ['T1021.002', 'T1543.003', 'T1569.002'],
             'encoded_powershell': ['T1059.001', 'T1027'],
             'script_c2_beacon': ['T1071.001']}

DETECTORS = [detect_brute_force, detect_lateral_movement, detect_exfiltration,
             detect_remote_service_exec, detect_encoded_powershell, detect_script_beacon]


def run_all(df: pd.DataFrame) -> list[dict]:
    alerts = [a for detector in DETECTORS for a in detector(df)]
    for i, a in enumerate(sorted(alerts, key=lambda a: a["time"]), 1):
        a["id"] = f"ALERT-{i:03d}"
        a["rule_tags"] = RULE_TAGS.get(a["type"], [])
    return sorted(alerts, key=lambda a: a["time"])


if __name__ == "__main__":
    import sys
    from . import scenarios
    name = sys.argv[1] if len(sys.argv) > 1 else scenarios.DEFAULT
    df = load_logs(scenarios.path(name) / "logs.jsonl")
    print(f"Scanned {len(df):,} events")
    for a in run_all(df):
        print(f"[{a['severity'].upper():8}] {a['id']} {a['type']}: {a['summary']}")
