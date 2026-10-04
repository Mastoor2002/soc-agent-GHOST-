"""
STEP 1b — Load REAL attack data recorded by security researchers.

WHY: Our synthetic attack proves the pipeline works, but judges (and real SOC
teams) want to see it catch attacks it didn't write itself. The OTRF Security
Datasets project ran real attack tools (Empire, Covenant, Mimikatz...) in a lab
Windows domain and recorded every log event, labeled with the MITRE technique.
Project: https://github.com/OTRF/Security-Datasets

Windows logs look NOTHING like our synthetic ones: thousands of event types,
different field names, mostly background noise. This file "normalizes" them —
translates the handful of event types that matter into GHOST's common schema,
so the same detectors, agent and dashboard work on both.

The Windows events we keep (the rest is noise for our purposes):
  4624 / 4625  Security    logon success / failure            -> source "auth"
  4688 / Sysmon 1          a process started (with command)   -> source "process"
  7045 / 4697              a new Windows service was installed-> source "service"
  Sysmon 3                 a network connection was made      -> source "network"
  Sysmon 10 (to lsass.exe) a program opened the password store's memory -> "process_access"
Everything else is kept as source "other" — the haystack the attack hides in.

Run:  python -m src.load_otrf
"""
import io
import json
import urllib.request
import zipfile
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

# All OTRF Windows datasets come from the same lab domain ("theshire.local"):
# workstations 172.18.39.x, servers 172.18.38.x, attacker server outside that range.
LAB = {
    "source_url": "https://github.com/OTRF/Security-Datasets",
    "known_subnets": ["172.18.0.0/16"],
    "threat_intel": {},
    "users": {
        "pgustavo": {"role": "Domain user (lab)", "normal_hosts": ["WORKSTATION5"], "admin": "unknown"},
        "sbeavers": {"role": "Domain user (lab)", "normal_hosts": ["WORKSTATION6"], "admin": "unknown"},
    },
    "directory_note": "Lab environment: the dataset does not include real job roles.",
    "chart_note": "Real recordings are short: a few minutes of a busy Windows network.",
}


def otrf(otrf_id, path, title, description, technique, label_name, benign=()):
    """One dataset entry. Ground truth = the dataset's OFFICIAL label, not our opinion.
    `benign` lists legitimate activity that a detector may flag: the agent is expected
    to dismiss it as a false positive."""
    return {"otrf_id": otrf_id, "url": f"{RAW}/{path}",
            "context": {**LAB, "title": title, "description": description},
            "truth": [{"stage": label_name, "mitre": [technique],
                       "note": f"Official OTRF label for {otrf_id}"}] + list(benign)}


DATASETS = {
    "real_psexec": otrf(
        "SDWIN-190518210652", "lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
        "Real attack: Empire Invoke-PsExec (OTRF)",
        "An attacker with a foothold on WORKSTATION5 uses the Empire framework to move to "
        "WORKSTATION6 by remotely creating and starting a Windows service over RPC/TCP.",
        "T1021", "lateral_movement"),
    "real_smbexec": otrf(
        "SDWIN-190518210125", "lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip",
        "Real attack: Empire Invoke-SMBExec (OTRF)",
        "A PsExec cousin: the attacker remotely creates and starts a service on WORKSTATION6, "
        "this time through SMB named pipes instead of plain RPC over TCP.",
        "T1021.002", "lateral_movement",
        benign=[{"stage": "benign", "benign": True,
                 "match": {"type": "lsass_memory_access", "process": "CollectGuestLogs.exe"},
                 "note": "Microsoft Azure guest agent (C:\\WindowsAzure\\GuestAgent...) reading "
                         "lsass while collecting diagnostic logs: legitimate, should be dismissed"}]),
    "real_wmi": otrf(
        "SDWIN-200921001437", "lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip",
        "Real attack: Empire Invoke-WMI (OTRF)",
        "Lateral movement through a different Windows feature: the attacker uses WMI "
        "(Win32_Process.Create) to run code on another machine. No service is created.",
        "T1047", "remote_execution"),
    "real_mimikatz": otrf(
        "SDWIN-190518202151", "credential_access/host/empire_mimikatz_logonpasswords.zip",
        "Real attack: Mimikatz LogonPasswords (OTRF)",
        "Credential theft: from WORKSTATION5 the attacker runs Mimikatz through Empire to read "
        "passwords and hashes out of the memory of lsass.exe, the Windows login process.",
        "T1003.001", "credential_dumping"),
}


def short_host(h) -> str | None:
    """'WORKSTATION6.theshire.local' -> 'WORKSTATION6' (the logs mix both spellings)."""
    return str(h).split(".")[0].upper() if h else None


def ts(e) -> str:
    # '2020-09-20T16:16:58.214Z' -> naive UTC '2020-09-20T16:16:58.214' (always 3 decimals)
    raw = str(e.get("@timestamp") or e.get("UtcTime")).replace("Z", "").replace(" ", "T")
    main, _, frac = raw.partition(".")
    return f"{main}.{(frac + '000')[:3]}"


def clean_user(u) -> str | None:
    if not u or u in ("-", "SYSTEM"):
        return u or None
    return str(u).split("\\")[-1]


def normalize(e: dict) -> dict | None:
    """Translate one Windows event into GHOST's schema, or None to skip it."""
    eid = e.get("EventID")
    channel = str(e.get("Channel", "")).lower()
    host = short_host(e.get("Hostname"))
    base = {"timestamp": ts(e), "host": host, "raw_event_id": int(eid) if str(eid).isdigit() else eid}

    if channel == "security" and eid in (4624, 4625):
        user = e.get("TargetUserName")
        if not user or str(user).endswith("$"):  # computer accounts = machine-to-machine noise
            return None
        lt = str(e.get("LogonType"))
        return {**base, "source": "auth", "event": "login",
                "outcome": "success" if eid == 4624 else "failure",
                "user": clean_user(user), "src_ip": e.get("IpAddress"),
                "method": {"2": "interactive", "3": "network", "10": "remote_desktop"}.get(lt, f"type{lt}")}

    if (channel == "security" and eid == 4688) or ("sysmon" in channel and eid == 1):
        return {**base, "source": "process", "event": "process_start",
                "user": clean_user(e.get("User") or e.get("SubjectUserName")),
                "process": e.get("Image") or e.get("NewProcessName"),
                "parent_process": e.get("ParentImage") or e.get("ParentProcessName"),
                "command_line": e.get("CommandLine")}

    if (channel == "system" and eid == 7045) or (channel == "security" and eid == 4697):
        return {**base, "source": "service", "event": "service_install",
                "user": clean_user(e.get("SubjectUserName") or e.get("AccountName")),
                "service_name": e.get("ServiceName"),
                "command_line": e.get("ImagePath") or e.get("ServiceFileName")}

    if "sysmon" in channel and eid == 3:
        return {**base, "source": "network", "event": "connection",
                "user": clean_user(e.get("User")), "process": e.get("Image"),
                "src_ip": e.get("SourceIp"), "dst_ip": e.get("DestinationIp"),
                "dst_port": int(e["DestinationPort"]) if e.get("DestinationPort") else None}

    # A program opening lsass.exe — the process holding logged-in users' passwords/hashes
    if "sysmon" in channel and eid == 10 and "lsass.exe" in str(e.get("TargetImage", "")).lower():
        return {**base, "source": "process_access", "event": "open_process",
                "user": clean_user(e.get("SourceUser")), "process": e.get("SourceImage"),
                "target_process": e.get("TargetImage"), "granted_access": e.get("GrantedAccess"),
                "call_trace": str(e.get("CallTrace", ""))[:400]}

    # Background noise: registry edits, DLL loads, PowerShell engine events... Kept so
    # detection scans the full haystack, but only a few fields (no huge payloads).
    return {**base, "source": "other", "event": f"{e.get('Channel')} {eid}",
            "user": clean_user(e.get("User") or e.get("SubjectUserName") or e.get("AccountName")),
            "process": e.get("Image") or e.get("SourceImage") or e.get("NewProcessName")}


def dedupe_processes(events: list[dict]) -> list[dict]:
    """Windows logs each program launch twice (Security 4688 AND Sysmon 1, which has
    more detail). Drop the 4688 copy when Sysmon saw the same launch within 3 seconds."""
    from datetime import datetime
    t = lambda e: datetime.fromisoformat(e["timestamp"])
    sysmon = [e for e in events if e["source"] == "process" and e["raw_event_id"] == 1]
    keep = []
    for e in events:
        if e["source"] == "process" and e["raw_event_id"] == 4688:
            same = lambda s: (s["host"] == e["host"]
                              and str(s.get("process", "")).lower() == str(e.get("process", "")).lower()
                              and s.get("command_line") == e.get("command_line")
                              and abs((t(s) - t(e)).total_seconds()) <= 3)
            if any(same(s) for s in sysmon):
                continue
        keep.append(e)
    return keep


def load(name: str) -> None:
    spec = DATASETS[name]
    print(f"Downloading {spec['otrf_id']} ...")
    with urllib.request.urlopen(spec["url"]) as r:
        z = zipfile.ZipFile(io.BytesIO(r.read()))
    raw_lines = []
    for member in z.namelist():
        if member.endswith(".json"):
            raw_lines += z.read(member).decode("utf-8").splitlines()

    from datetime import datetime
    events, services = [], []
    for line in raw_lines:
        n = normalize(json.loads(line))
        if not n:
            continue
        # 7045 and 4697 both describe the same service install (a fraction of a second
        # apart, sometimes across a second boundary) — keep one
        if n["source"] == "service":
            t = datetime.fromisoformat(n["timestamp"])
            if any(h == n["host"] and name == n.get("service_name") and abs((t - t0).total_seconds()) <= 5
                   for h, name, t0 in services):
                continue
            services.append((n["host"], n.get("service_name"), t))
        events.append({k: v for k, v in n.items() if v not in (None, "", "-")})
    events = dedupe_processes(events)
    events.sort(key=lambda e: e["timestamp"])

    out = DATA_DIR / name
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "logs.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    (out / "ground_truth.json").write_text(json.dumps(spec["truth"], indent=2))
    (out / "context.json").write_text(json.dumps(
        {**spec["context"], "otrf_id": spec["otrf_id"], "raw_events": len(raw_lines)}, indent=2))
    relevant = sum(e["source"] != "other" for e in events)
    print(f"{len(raw_lines):,} raw Windows events -> {len(events):,} after removing duplicates "
          f"({relevant} security-relevant, the rest background noise) -> data/{name}/")


if __name__ == "__main__":
    import sys
    for name in (sys.argv[1:] or DATASETS):
        load(name)
