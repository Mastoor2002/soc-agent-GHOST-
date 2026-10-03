"""
STEP 1 — Generate realistic security logs with a hidden attack inside.

WHY: Real SOC tools read logs from firewalls, VPNs, and servers. For a hackathon
you need data where YOU know the right answer, so you can prove your agent works.
This script makes a day of "normal" company activity and secretly plants a
3-stage attack in it. The answer key goes in a separate file (ground_truth.json)
so the detector and agent can never cheat by reading it.
It also writes context.json: what the company's SOC already knows (IP ranges,
employee directory, threat-intel feed). See src/scenarios.py.

The attack chain (a classic real-world pattern):
  1. Brute force   — an outside IP guesses the VPN password for user 'jsmith' and gets in
  2. Lateral move  — the attacker uses jsmith's account to log into several internal servers
  3. Exfiltration  — a huge amount of data is sent out of the file server at 3 AM

Later you can swap this for a real public dataset (Splunk BOTS v3, CIC-IDS2017,
LANL auth logs). The rest of the pipeline won't care, as long as the columns match.

Run:  python -m src.generate_logs        (writes data/synthetic/)
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)  # same "random" data every run, so results are reproducible

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"
DAY = datetime(2026, 10, 1)

USERS = [f"user{i:02d}" for i in range(1, 41)] + ["jsmith", "admin_kim"]
WORKSTATIONS = [f"WS-{i:02d}" for i in range(1, 31)]
SERVERS = ["FS-01", "DB-01", "DC-01", "WEB-01", "HR-APP"]
INTERNAL_NET = "10.0.{}.{}"
ATTACKER_IP = "185.220.101.47"   # looks like a Tor exit node
EXFIL_IP = "45.137.21.9"         # attacker-controlled server

# Each user "owns" a workstation — this is what normal looks like for them.
HOME_WS = {u: random.choice(WORKSTATIONS) for u in USERS}
HOME_WS["jsmith"] = "WS-07"


# What this company's SOC already knows — the agent's tools read this
CONTEXT = {
    "title": "Practice attack (synthetic)",
    "description": "A simulated day at a 42-person company with a hidden 3-stage attack: "
                   "VPN brute force, lateral movement, and data exfiltration.",
    "chart_note": "The red spike around 2 AM is the brute-force attack.",
    "known_subnets": ["10.0.0.0/8"],
    "threat_intel": {
        ATTACKER_IP: {"verdict": "malicious", "tags": ["tor-exit-node", "credential-stuffing"],
                      "reports": 412, "country": "DE"},
        EXFIL_IP: {"verdict": "malicious", "tags": ["known-c2", "data-exfil-infra"],
                   "reports": 88, "country": "NL"},
    },
    "users": {
        "jsmith": {"role": "Marketing Coordinator", "normal_hosts": ["WS-07", "FS-01"],
                   "works_remote": False, "admin": False},
        "admin_kim": {"role": "IT Administrator", "normal_hosts": ["DC-01", "FS-01", "DB-01"],
                      "works_remote": True, "admin": True},
    },
    "directory_note": "Normal employees use their own workstation plus FS-01/WEB-01/HR-APP.",
}


def ip_for(host: str) -> str:
    """Give every host a stable internal IP address."""
    n = sum(ord(c) * (i + 1) for i, c in enumerate(host)) % 250 + 2  # deterministic
    return INTERNAL_NET.format(1 if host.startswith("WS") else 2, n)


def ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def normal_activity() -> list[dict]:
    """Ordinary business-day noise: logins, a few typos, web browsing, file access."""
    events = []
    for user in USERS:
        start = DAY + timedelta(hours=random.uniform(7.5, 9.5))
        ws = HOME_WS[user]
        # Occasional typo before a successful login — normal humans do this!
        if random.random() < 0.25:
            for _ in range(random.randint(1, 3)):
                events.append({"timestamp": ts(start), "source": "auth", "event": "login",
                               "outcome": "failure", "user": user, "host": ws,
                               "src_ip": ip_for(ws), "method": "interactive"})
                start += timedelta(seconds=random.randint(5, 30))
        events.append({"timestamp": ts(start), "source": "auth", "event": "login",
                       "outcome": "success", "user": user, "host": ws,
                       "src_ip": ip_for(ws), "method": "interactive"})

        # One or two normal server visits (e.g., opening a shared drive)
        for _ in range(random.randint(0, 2)):
            t = start + timedelta(hours=random.uniform(0.5, 7))
            srv = random.choice(["FS-01", "WEB-01", "HR-APP"])
            events.append({"timestamp": ts(t), "source": "auth", "event": "login",
                           "outcome": "success", "user": user, "host": srv,
                           "src_ip": ip_for(ws), "method": "network"})

        # Web traffic through the firewall — small, frequent
        for _ in range(random.randint(15, 40)):
            t = start + timedelta(minutes=random.uniform(0, 540))
            events.append({"timestamp": ts(t), "source": "firewall", "event": "connection",
                           "action": "allow", "host": ws, "src_ip": ip_for(ws),
                           "dst_ip": f"{random.randint(20, 220)}.{random.randint(0, 255)}."
                                     f"{random.randint(0, 255)}.{random.randint(1, 254)}",
                           "dst_port": random.choice([443, 443, 443, 80, 53]),
                           "bytes_out": random.randint(500, 400_000)})

    # Nightly backup: big transfer, but to an INTERNAL known host — a false-positive trap.
    events.append({"timestamp": ts(DAY + timedelta(hours=1)), "source": "firewall",
                   "event": "connection", "action": "allow", "host": "FS-01",
                   "src_ip": ip_for("FS-01"), "dst_ip": "10.0.9.10", "dst_port": 445,
                   "bytes_out": 2_400_000_000})
    return events


def attack_chain() -> tuple[list[dict], list[dict]]:
    """Plant the attack. Returns (log events, ground-truth labels)."""
    events, truth = [], []

    # Stage 1 — Brute force against VPN (T1110), then success (T1078 valid account)
    t = DAY + timedelta(hours=2, minutes=14)
    for _ in range(37):
        events.append({"timestamp": ts(t), "source": "auth", "event": "login",
                       "outcome": "failure", "user": "jsmith", "host": "VPN-GW",
                       "src_ip": ATTACKER_IP, "method": "vpn"})
        t += timedelta(seconds=random.randint(3, 12))
    events.append({"timestamp": ts(t), "source": "auth", "event": "login",
                   "outcome": "success", "user": "jsmith", "host": "VPN-GW",
                   "src_ip": ATTACKER_IP, "method": "vpn"})
    truth.append({"stage": "brute_force", "time": ts(t), "user": "jsmith",
                  "ip": ATTACKER_IP, "mitre": ["T1110", "T1078"]})

    # Stage 2 — Lateral movement across servers (T1021 remote services)
    t += timedelta(minutes=6)
    for srv in ["WS-14", "DB-01", "FS-01", "DC-01"]:
        events.append({"timestamp": ts(t), "source": "auth", "event": "login",
                       "outcome": "success", "user": "jsmith", "host": srv,
                       "src_ip": ip_for("WS-07"), "method": "network"})
        t += timedelta(minutes=random.randint(2, 5))
    truth.append({"stage": "lateral_movement", "time": ts(t), "user": "jsmith",
                  "hosts": ["WS-14", "DB-01", "FS-01", "DC-01"], "mitre": ["T1021"]})

    # Stage 3 — Exfiltration to an outside server (T1048)
    t = DAY + timedelta(hours=3, minutes=2)
    for _ in range(6):
        events.append({"timestamp": ts(t), "source": "firewall", "event": "connection",
                       "action": "allow", "host": "FS-01", "src_ip": ip_for("FS-01"),
                       "dst_ip": EXFIL_IP, "dst_port": 8443,
                       "bytes_out": random.randint(300_000_000, 600_000_000)})
        t += timedelta(minutes=3)
    truth.append({"stage": "exfiltration", "time": ts(t), "host": "FS-01",
                  "ip": EXFIL_IP, "mitre": ["T1048"]})
    return events, truth


def main():
    DATA_DIR.mkdir(exist_ok=True)
    attack_events, truth = attack_chain()
    events = normal_activity() + attack_events
    events.sort(key=lambda e: e["timestamp"])  # logs arrive in time order

    # JSON Lines: one JSON object per line — the most common log-shipping format.
    with open(DATA_DIR / "logs.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    with open(DATA_DIR / "ground_truth.json", "w") as f:
        json.dump(truth, f, indent=2)
    with open(DATA_DIR / "context.json", "w") as f:
        json.dump(CONTEXT, f, indent=2)

    print(f"Wrote {len(events):,} log events -> data/synthetic/logs.jsonl")
    print(f"Planted {len(truth)} attack stages -> data/synthetic/ground_truth.json (the answer key)")


if __name__ == "__main__":
    main()
