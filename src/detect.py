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
           "process", "parent_process", "command_line", "service_name",
           "target_process", "granted_access", "call_trace"]


def load_logs(path=LOG_FILE) -> pd.DataFrame:
    with open(path) as f:
        df = pd.DataFrame([json.loads(line) for line in f])
    for c in COLUMNS:
        if c not in df:
            df[c] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    return df.sort_values("timestamp").reset_index(drop=True)


def _basenames(col: pd.Series) -> pd.Series:
    """Vectorized _basename for a whole column. Column-wide string operations run on
    the GPU under RAPIDS cudf.pandas; a Python function applied row by row cannot."""
    return (col.fillna("").astype(str).str.replace("/", "\\", regex=False)
            .str.split("\\").str[-1].str.lower())


def _basename(path) -> str:
    """'C:\\Windows\\System32\\cmd.exe' -> 'cmd.exe'"""
    return str(path).replace("/", "\\").split("\\")[-1].lower()


def _first_per(rows: pd.DataFrame, keys: list[str]) -> list[dict]:
    """The first row of each group (in log order) plus the group's size, as plain dicts,
    sorted by the keys. Same result as looping over groupby(keys) and taking g.iloc[0],
    but done in two table-wide operations: much faster on millions of rows and on a GPU,
    where a Python loop over thousands of groups is the slowest thing you can do."""
    rows = rows.dropna(subset=keys)
    if rows.empty:
        return []
    firsts = rows.drop_duplicates(keys)
    sizes = rows.groupby(keys).size().rename("n").reset_index()
    firsts = firsts.merge(sizes, on=keys).sort_values(keys)
    return firsts.to_dict("records")


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
    span = pd.Timedelta(window)
    for user, g in net.groupby("user"):
        g = g.sort_values("timestamp")
        times, hosts = g.timestamp.tolist(), g.host.tolist()
        # Sliding window: j moves forward only, so this is linear, not quadratic.
        # (A nested loop here took minutes on millions of events.)
        seen, j = {}, 0
        for i in range(len(times)):
            while j < len(times) and times[j] - times[i] <= span:
                seen[hosts[j]] = seen.get(hosts[j], 0) + 1
                j += 1
            if len(seen) >= min_hosts:
                in_window = sorted(seen)
                alerts.append({
                    "type": "lateral_movement",
                    "severity": "high",
                    "time": str(times[i]),
                    "user": user,
                    "hosts": in_window,
                    "summary": f"{user} logged into {len(in_window)} hosts within {window}: "
                               f"{', '.join(in_window)}",
                })
                break  # one alert per user is enough
            seen[hosts[i]] -= 1  # event i leaves the window
            if not seen[hosts[i]]:
                del seen[hosts[i]]
    return alerts


def detect_exfiltration(df: pd.DataFrame, mb_threshold: float = 500) -> list[dict]:
    """Large volumes of data leaving to an EXTERNAL address.
    Internal backups (10.x.x.x) are excluded — that's the false-positive trap."""
    fw = df[(df.source == "firewall") & ~df.dst_ip.astype(str).str.startswith("10.")]
    totals = fw.groupby(["host", "dst_ip"]).agg(  # built-in aggregations only: GPU-friendly
        total_bytes=("bytes_out", "sum"),
        first=("timestamp", "min"),
        conns=("bytes_out", "size"),
    ).reset_index()
    totals["mb"] = totals["total_bytes"] / 1e6
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
    services = df[df.source == "service"].reset_index(drop=True)
    if services.empty:
        return []
    services["sid"] = range(len(services))
    who = _remote_logons_near(df, services, window_s)
    services = services.merge(who, on="sid", how="left").sort_values("sid")
    stems = "|".join(sh.split(".")[0] for sh in SHELLS)
    services["runs_shell"] = services.command_line.fillna("").astype(str).str.lower().str.contains(stems)
    services["matched"] = services["matched"].fillna(False).astype(bool)
    alerts = []
    for svc in services[services.matched | services.runs_shell].to_dict("records"):
        alerts.append({
            "type": "remote_service_execution",
            "severity": "critical" if (svc["matched"] and svc["runs_shell"]) else "high",
            "time": str(svc["timestamp"]),
            "host": svc["host"],
            "user": svc["who_user"] if svc["matched"] else svc["user"],
            "src_ip": svc["who_ip"] if svc["matched"] else None,
            "service_name": svc["service_name"],
            "summary": (f"New service '{svc['service_name']}' on {svc['host']} runs a command shell"
                        + (f", seconds after a network logon by {svc['who_user']} from {svc['who_ip']}"
                           if svc["matched"] else "")),
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
    for first in _first_per(procs, ["host"]):
        alerts.append({
            "type": "encoded_powershell",
            "severity": "high",
            "time": str(first["timestamp"]),
            "host": first["host"],
            "user": first["user"],
            "parent_process": _basename(first["parent_process"]),
            "summary": f"PowerShell with a hidden (base64-encoded) command ran on {first['host']} as "
                       f"{first['user']}, launched by {_basename(first['parent_process'])}",
        })
    return alerts


def detect_script_beacon(df: pd.DataFrame) -> list[dict]:
    """A command shell or script engine making a web connection. Browsers talk to
    the web; PowerShell running as SYSTEM usually shouldn't — it's a classic C2 callback."""
    net = df[(df.source == "network") & df.dst_port.isin([80, 443, 8080, 8443])]
    net = net[_basenames(net.process).isin(SHELLS)]  # string work only on the rows left
    alerts = []
    for first in _first_per(net, ["host", "dst_ip"]):
        alerts.append({
            "type": "script_c2_beacon",
            "severity": "high",
            "time": str(first["timestamp"]),
            "host": first["host"],
            "user": first["user"],
            "dst_ip": first["dst_ip"],
            "summary": f"{_basename(first['process'])} on {first['host']} (as {first['user']}) connected to "
                       f"{first['dst_ip']}:{int(first['dst_port'])} — {first['n']} connection(s)",
        })
    return alerts


def _remote_logons_near(df, events, window_s=120):
    """For each row of `events` (needs columns sid, host, timestamp): the FIRST successful
    remote network logon on the same host within `window_s` seconds. One join over the
    whole table instead of re-scanning every log for every event, so it stays fast on
    millions of rows (and runs as GPU joins under RAPIDS)."""
    logons = df[(df.source == "auth") & (df.outcome == "success") & (df.method == "network")
                & ~df.src_ip.isin(["::1", "127.0.0.1", "-"])][["host", "timestamp", "user", "src_ip"]]
    logons = logons.reset_index(drop=True)
    logons["lid"] = range(len(logons))  # original log order: "first" means earliest listed
    m = events[["sid", "host", "timestamp"]].merge(logons, on="host", suffixes=("", "_l"))
    m = m[(m.timestamp_l - m.timestamp).abs().dt.total_seconds() <= window_s]
    m = m.sort_values(["sid", "lid"]).drop_duplicates("sid")
    out = m[["sid", "user", "src_ip"]].rename(columns={"user": "who_user", "src_ip": "who_ip"})
    out["matched"] = True
    return out


def detect_wmi_remote_exec(df: pd.DataFrame) -> list[dict]:
    """WMI lateral movement: wmiprvse.exe (the Windows WMI service) launches a command
    shell, and someone logged in to that machine over the network at the same moment.
    Admin tools rarely spawn shells through WMI; attack frameworks do it constantly."""
    procs = df[df.source == "process"]
    if procs.empty:
        return []
    procs = procs[(_basenames(procs.parent_process) == "wmiprvse.exe")
                  & _basenames(procs.process).isin(SHELLS)]
    firsts = procs.drop_duplicates("host").sort_values("host").reset_index(drop=True)
    firsts["sid"] = range(len(firsts))
    who = _remote_logons_near(df, firsts)
    firsts = firsts.merge(who, on="sid", how="left").sort_values("sid")
    firsts["matched"] = firsts["matched"].fillna(False).astype(bool)
    alerts = []
    for r in firsts.to_dict("records"):
        hit = r["matched"]
        alerts.append({
            "type": "remote_wmi_execution",
            "severity": "critical" if hit else "high",
            "time": str(r["timestamp"]), "host": r["host"],
            "user": r["who_user"] if hit else r["user"],
            "src_ip": r["who_ip"] if hit else None,
            "summary": f"WMI (wmiprvse.exe) launched {_basename(r['process'])} on {r['host']} as "
                       f"{r['user']}" + (f", at the same moment as a network logon by {r['who_user']} "
                                         f"from {r['who_ip']}" if hit else ""),
        })
    return alerts


def detect_lsass_access(df: pd.DataFrame) -> list[dict]:
    """Credential dumping: a program opens lsass.exe (which holds logged-in users'
    password hashes) with permission to READ ITS MEMORY (access bit 0x10) — exactly what
    Mimikatz does. Some legitimate tools (antivirus, diagnostics agents) do this too, so:
      critical = a script engine/shell, or code running from memory with no file behind
                 it ('UNKNOWN' in the call trace) — classic in-memory Mimikatz
      medium   = any other program: worth a look, often legitimate"""
    acc = df[(df.source == "process_access")
             & df.target_process.astype(str).str.lower().str.endswith("lsass.exe")]
    if acc.empty:  # this dataset has no lsass access events at all
        return []
    acc = acc[acc.granted_access.apply(lambda a: bool(int(str(a), 16) & 0x10) if a else False)]
    alerts = []
    for first in _first_per(acc, ["host", "process"]):
        host, proc = first["host"], first["process"]
        from_memory = "UNKNOWN" in str(first["call_trace"])
        scripted = _basename(proc) in SHELLS
        alerts.append({
            "type": "lsass_memory_access",
            "severity": "critical" if (from_memory or scripted) else "medium",
            "time": str(first["timestamp"]), "host": host, "user": first["user"],
            "process": proc, "granted_access": first["granted_access"],
            "summary": f"{_basename(proc)} on {host} opened lsass.exe with memory-read access "
                       f"({first['granted_access']})"
                       + (" from code with no file on disk (UNKNOWN in call trace)" if from_memory else ""),
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
             'script_c2_beacon': ['T1071.001'],
             'remote_wmi_execution': ['T1047'],
             'lsass_memory_access': ['T1003.001']}

DETECTORS = [detect_brute_force, detect_lateral_movement, detect_exfiltration,
             detect_remote_service_exec, detect_encoded_powershell, detect_script_beacon,
             detect_wmi_remote_exec, detect_lsass_access]


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
