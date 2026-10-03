"""
STEP 4 — The agent's tools (what the LLM is allowed to DO).

WHY: An LLM by itself can only talk. "Tool calling" lets it ask your code to
run a function, read the result, and decide what to do next — exactly like an
analyst who runs a query, reads it, then runs another.

How it works:
  1. You describe each tool to the model in JSON Schema (TOOL_SCHEMAS below).
  2. The model replies: "call query_logs with user='jsmith'".
  3. YOUR code runs the Python function and sends the result back.
  4. Repeat until the model writes its final report.

The model never touches your system directly — it can only request these exact
functions. That's an important security property worth mentioning to judges.

Some tools here use small local lookup tables so everything works offline.
Upgrade ideas: ip_reputation -> AbuseIPDB or VirusTotal API; mitre_lookup ->
vector search over the full MITRE ATT&CK dataset (that's the RAG part of the plan).
"""
import json

import pandas as pd

# ---- Mini threat-intel feed (swap for a real API later) ----
THREAT_INTEL = {
    "185.220.101.47": {"verdict": "malicious", "tags": ["tor-exit-node", "credential-stuffing"],
                        "reports": 412, "country": "DE"},
    "45.137.21.9": {"verdict": "malicious", "tags": ["known-c2", "data-exfil-infra"],
                    "reports": 88, "country": "NL"},
}

# ---- Mini MITRE ATT&CK knowledge base (swap for RAG over the full dataset) ----
MITRE = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "mitigation": "Enforce MFA, account lockout, block source IP"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access / Persistence",
              "mitigation": "Reset credentials, review session activity, enforce MFA"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "mitigation": "Restrict admin protocols, segment network, disable compromised account"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
              "mitigation": "Block destination, egress filtering, DLP on file servers"},
    "T1550": {"name": "Use Alternate Authentication Material (pass-the-hash/ticket)",
              "tactic": "Lateral Movement", "mitigation": "Reset Kerberos tickets, restrict NTLM"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
              "mitigation": "Block SMB file copies between workstations"},
}
KEYWORDS = {"brute": "T1110", "password": "T1110", "failed login": "T1110",
            "valid account": "T1078", "compromised account": "T1078",
            "lateral": "T1021", "remote": "T1021", "smb": "T1021", "rdp": "T1021",
            "exfil": "T1048", "data transfer": "T1048", "upload": "T1048",
            "credential access": "T1110", "successful login": "T1078", "stolen credential": "T1078",
            "vpn": "T1078", "pass the hash": "T1550", "pass the ticket": "T1550",
            "tool transfer": "T1570"}

# ---- Directory info (in real life: Active Directory / Okta) ----
USERS = {
    "jsmith": {"role": "Marketing Coordinator", "normal_hosts": ["WS-07", "FS-01"],
               "works_remote": False, "admin": False},
    "admin_kim": {"role": "IT Administrator", "normal_hosts": ["DC-01", "FS-01", "DB-01"],
                  "works_remote": True, "admin": True},
}


class Toolbox:
    """Holds the log data so tools can query it."""

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def query_logs(self, user=None, host=None, ip=None, start=None, end=None, limit=25):
        """Search logs — the agent's main investigation tool."""
        d = self.df
        if user:
            d = d[d.user == user]
        if host:
            d = d[d.host == host]
        if ip:
            d = d[(d.src_ip == ip) | (d.dst_ip == ip)]
        if start:
            d = d[d.timestamp >= pd.to_datetime(start)]
        if end:
            d = d[d.timestamp <= pd.to_datetime(end)]
        total = len(d)
        rows = d.head(limit).dropna(axis=1, how="all").astype(str).to_dict("records")
        return {"total_matches": total, "showing": len(rows), "events": rows}

    def ip_reputation(self, ip):
        if ip.startswith("10."):
            return {"ip": ip, "verdict": "internal", "note": "Private company address"}
        return {"ip": ip, **THREAT_INTEL.get(ip, {"verdict": "unknown", "reports": 0})}

    def mitre_lookup(self, behavior):
        b = behavior.lower()
        ids = sorted({tid for kw, tid in KEYWORDS.items() if kw in b})
        if behavior.upper() in MITRE:
            ids = [behavior.upper()]
        if ids:
            return {"matches": [{"id": i, **MITRE[i]} for i in ids]}
        # No match: show the whole (small) list so the model picks instead of guessing forever
        return {"matches": [], "note": "No keyword match. Choose from these known techniques:",
                "available": {i: m["name"] for i, m in MITRE.items()}}

    def get_user_context(self, user):
        return USERS.get(user, {"role": "Employee", "normal_hosts": "own workstation",
                                "works_remote": False, "admin": False})

    def run(self, name: str, args: dict) -> str:
        """Dispatch a tool call from the model. Always returns a JSON string."""
        try:
            fn = getattr(self, name)
            return json.dumps(fn(**args), default=str)
        except Exception as e:  # tell the model what went wrong so it can retry
            return json.dumps({"error": f"{type(e).__name__}: {e}"})


# JSON Schema descriptions the MODEL reads to know what tools exist.
# Good descriptions matter a lot — this is prompt engineering for tools.
TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "query_logs",
        "description": "Search security logs. Filter by user, host, IP (matches source or "
                       "destination), and ISO time range. Use this to gather evidence.",
        "parameters": {"type": "object", "properties": {
            "user": {"type": "string"}, "host": {"type": "string"},
            "ip": {"type": "string"},
            "start": {"type": "string", "description": "ISO time, e.g. 2026-10-01T02:00:00"},
            "end": {"type": "string"},
            "limit": {"type": "integer", "default": 25}}}}},
    {"type": "function", "function": {
        "name": "ip_reputation",
        "description": "Check threat intelligence for an IP address: malicious, unknown, or internal.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}},
                       "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "mitre_lookup",
        "description": "Map a behavior description (e.g. 'brute force', 'lateral movement') "
                       "or technique ID to MITRE ATT&CK techniques and mitigations.",
        "parameters": {"type": "object", "properties": {"behavior": {"type": "string"}},
                       "required": ["behavior"]}}},
    {"type": "function", "function": {
        "name": "get_user_context",
        "description": "Get a user's role, normal hosts, and whether they work remotely. "
                       "Use this to judge if activity is unusual FOR THIS PERSON.",
        "parameters": {"type": "object", "properties": {"user": {"type": "string"}},
                       "required": ["user"]}}},
]
