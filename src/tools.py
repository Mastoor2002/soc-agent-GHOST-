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

Company knowledge (IP ranges, employee directory, threat intel) comes from the
scenario's context.json, so the same tools work on any dataset.
mitre_lookup searches two things: a small hand-checked table (MITRE below) whose
matches count as evidence for the grounding check, and the FULL MITRE ATT&CK
knowledge base (data/attack/, ~700 techniques, built by build_attack_index.py),
whose search results are reference only: the agent can read official names,
descriptions and mitigations, but a technique it finds there still needs evidence.
Upgrade idea: ip_reputation -> AbuseIPDB or VirusTotal API.
"""
import base64
import ipaddress
import json
import math
import re
from collections import Counter
from pathlib import Path

import pandas as pd

# ---- Mini MITRE ATT&CK knowledge base (swap for RAG over the full dataset) ----
MITRE = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "mitigation": "Enforce MFA, account lockout, block source IP"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access / Persistence",
              "mitigation": "Reset credentials, review session activity, enforce MFA"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "mitigation": "Restrict admin protocols, segment network, disable compromised account"},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares (PsExec-style)",
                  "tactic": "Lateral Movement",
                  "mitigation": "Block admin shares between workstations, LAPS, restrict local admin"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
              "mitigation": "Block destination, egress filtering, DLP on file servers"},
    "T1550": {"name": "Use Alternate Authentication Material (pass-the-hash/ticket)",
              "tactic": "Lateral Movement", "mitigation": "Reset Kerberos tickets, restrict NTLM"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
              "mitigation": "Block SMB file copies between workstations"},
    "T1543.003": {"name": "Create or Modify System Process: Windows Service",
                  "tactic": "Persistence / Privilege Escalation",
                  "mitigation": "Alert on new services, restrict service creation rights"},
    "T1569.002": {"name": "System Services: Service Execution", "tactic": "Execution",
                  "mitigation": "Monitor services launching shells; restrict remote service control"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution",
                  "mitigation": "Constrained Language Mode, script block logging, AMSI"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
              "mitigation": "Decode and inspect encoded commands; alert on -enc usage"},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion",
                  "mitigation": "Protect logging settings; alert when AMSI/script logging is disabled"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols (C2 over HTTP/S)",
                  "tactic": "Command and Control",
                  "mitigation": "Block unknown destinations; proxy and inspect outbound web traffic"},
    "T1047": {"name": "Windows Management Instrumentation (WMI) remote execution",
              "tactic": "Execution / Lateral Movement",
              "mitigation": "Restrict remote WMI/DCOM, alert on shells spawned by wmiprvse.exe"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory (e.g. Mimikatz)",
                  "tactic": "Credential Access",
                  "mitigation": "Enable LSA Protection/Credential Guard; reset exposed passwords"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control",
              "mitigation": "Block downloads from untrusted hosts"},
    "T1033": {"name": "System Owner/User Discovery (e.g. whoami)", "tactic": "Discovery",
              "mitigation": "Alert on discovery commands run by SYSTEM from unusual parents"},
}
KEYWORDS = {"brute": "T1110", "password": "T1110", "failed login": "T1110",
            "credential access": "T1110",
            "valid account": "T1078", "compromised account": "T1078", "stolen credential": "T1078",
            "successful login": "T1078", "vpn": "T1078",
            "lateral": "T1021", "remote service": "T1021", "rdp": "T1021",
            "smb": "T1021.002", "admin share": "T1021.002", "psexec": "T1021.002",
            "exfil": "T1048", "data transfer": "T1048", "upload": "T1048",
            "pass the hash": "T1550", "pass the ticket": "T1550", "tool transfer": "T1570",
            "service install": "T1543.003", "new service": "T1543.003",
            "windows service": "T1543.003", "service creat": "T1543.003",
            "service execution": "T1569.002", "service launch": "T1569.002",
            "powershell": "T1059.001", "script": "T1059.001",
            "encoded": "T1027", "obfuscat": "T1027", "base64": "T1027",
            "disable logging": "T1562.001", "amsi": "T1562.001", "impair defense": "T1562.001",
            "script block logging": "T1562.001",
            "c2": "T1071.001", "command and control": "T1071.001", "beacon": "T1071.001",
            "callback": "T1071.001", "download": "T1105", "stager": "T1105",
            "whoami": "T1033", "discovery": "T1033",
            "wmi": "T1047", "wmiprvse": "T1047", "win32_process": "T1047",
            "lsass": "T1003.001", "credential dump": "T1003.001", "mimikatz": "T1003.001",
            "password hash": "T1003.001", "memory read": "T1003.001"}

# ---- Full MITRE ATT&CK knowledge base, searched with BM25 ----
# BM25 is the classic search-engine ranking: a word counts more when it is rare
# across all techniques and appears in this one. No extra libraries, no GPU, and
# every result can be explained, which matters for a security tool.
ATTACK_FILE = Path(__file__).resolve().parent.parent / "data" / "attack" / "enterprise_attack.json"
STOP = set("a an and are as at be by can for from has have in into is it its may of on or "
           "that the their them these this to use used uses using via was were which with "
           "adversaries adversary".split())


def _tokens(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return [w[:-1] if len(w) > 4 and w.endswith("s") else w for w in words if w not in STOP]


class AttackIndex:
    def __init__(self, path=ATTACK_FILE):
        data = json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {"techniques": {}}
        self.version = data.get("attack_version")
        self.techniques = data["techniques"]
        self.docs = {}
        for tid, t in self.techniques.items():
            # the name counts three times: it is the most precise description
            text = " ".join([tid, t["name"]] * 3 + t["tactics"] + [t["summary"]])
            self.docs[tid] = Counter(_tokens(text))
        n = len(self.docs) or 1
        self.lengths = {tid: sum(c.values()) for tid, c in self.docs.items()}
        self.avg_len = sum(self.lengths.values()) / n
        df = Counter(w for c in self.docs.values() for w in c)
        self.idf = {w: math.log(1 + (n - f + 0.5) / (f + 0.5)) for w, f in df.items()}

    def search(self, query: str, k: int = 5, exclude=()) -> list[dict]:
        ids = [t for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query.upper()) if t in self.techniques]
        q = _tokens(query)
        scores = {}
        for tid, c in self.docs.items():
            s = 0.0
            for w in q:
                f = c.get(w)
                if f:
                    s += self.idf[w] * f * 2.2 / (f + 1.2 * (0.25 + 0.75 * self.lengths[tid] / self.avg_len))
            if s:
                scores[tid] = s
        ranked = ids + [t for t, _ in sorted(scores.items(), key=lambda x: -x[1]) if t not in ids]
        return [{"id": t, **{f: self.techniques[t][f] for f in ("name", "tactics", "mitigations")},
                 "summary": self.techniques[t]["summary"][:240]}
                for t in ranked if t not in exclude][:k]


ATTACK = AttackIndex()


def technique_name(tid: str) -> str:
    """Display name for any technique ID: the hand-checked table first, then full ATT&CK."""
    return MITRE.get(tid, {}).get("name") or ATTACK.techniques.get(tid, {}).get("name", "")


# Columns that are mostly noise for the agent — dropped from query results
HIDE = {"raw_event_id"}
MAX_FIELD = 180  # long command lines are cut; use decode_command for the full text


class Toolbox:
    """Holds the log data + the scenario's company knowledge so tools can query it."""

    def __init__(self, df: pd.DataFrame, context: dict | None = None):
        self.df = df
        self.ctx = context or {}
        self.subnets = [ipaddress.ip_network(s) for s in self.ctx.get("known_subnets", [])]
        self.mitre_calls = 0

    def reset(self):
        """Called at the start of each investigation."""
        self.mitre_calls = 0

    # ---------------------------------------------------------------- tools
    def query_logs(self, user=None, host=None, ip=None, source=None, text=None,
                   start=None, end=None, limit=25):
        """Search logs — the agent's main investigation tool."""
        d = self.df
        if user:
            d = d[d.user.astype(str).str.contains(re.escape(user), case=False, na=False)]
        if host:
            d = d[d.host.astype(str).str.lower().str.startswith(host.lower())]
        if ip:
            d = d[(d.src_ip == ip) | (d.dst_ip == ip)]
        if source:
            d = d[d.source == source]
        else:  # background noise (registry edits, DLL loads...) only when asked for
            d = d[d.source != "other"]
        if text:  # free-text search across EVERY field (user, IPs, commands, event names...)
            hay = d.drop(columns=["timestamp"]).astype(str)
            d = d[hay.apply(lambda c: c.str.contains(re.escape(text), case=False, na=False))
                  .any(axis=1)]
        if start:
            d = d[d.timestamp >= pd.to_datetime(start)]
        if end:
            d = d[d.timestamp <= pd.to_datetime(end)]
        total = len(d)
        rows = []
        for r in d.head(int(limit)).to_dict("records"):
            clean = {}
            for k, v in r.items():
                if k in HIDE or v is None or (isinstance(v, float) and pd.isna(v)) or v == "":
                    continue
                s = str(v)
                clean[k] = s if len(s) <= MAX_FIELD else s[:MAX_FIELD] + "…[truncated]"
            rows.append(clean)
        return {"total_matches": total, "showing": len(rows), "events": rows}

    def ip_reputation(self, ip):
        intel = self.ctx.get("threat_intel", {})
        if ip in intel:
            return {"ip": ip, **intel[ip]}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"ip": ip, "verdict": "invalid address"}
        if any(addr in n for n in self.subnets):
            return {"ip": ip, "verdict": "internal", "note": "Inside the company's known network ranges"}
        if addr.is_private and not self.ctx.get("network_info", True):
            # Uploaded logs: we don't know the company's ranges, so say so, don't guess
            return {"ip": ip, "verdict": "private, ownership unknown",
                    "note": "Private (internal-style) address. These uploaded logs come with no "
                            "list of company network ranges, so it can't be confirmed as a "
                            "company asset or ruled out as attacker infrastructure."}
        if addr.is_private:
            return {"ip": ip, "verdict": "suspicious",
                    "note": "Private address but NOT in the company's known network ranges "
                            "(not a known company asset)"}
        if addr.is_loopback or addr.is_link_local:
            return {"ip": ip, "verdict": "local", "note": "Same machine / local link"}
        return {"ip": ip, "verdict": "unknown", "reports": 0}

    def mitre_lookup(self, behavior):
        self.mitre_calls += 1
        if self.mitre_calls > 3:  # the model was looping on lookups instead of deciding
            return {"error": "MITRE lookup limit reached for this alert. Use the techniques "
                             "you already found and write your final report."}
        b = behavior.lower()
        ids = {tid for kw, tid in KEYWORDS.items() if kw in b}
        # Technique IDs typed into the query ("T1021.002 T1543.003") are matched directly
        ids |= {t for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", behavior.upper()) if t in MITRE}
        ids = sorted(ids)
        # "matches" (hand-checked table) must come first in this dict: the grounding
        # check counts only the matches as evidence and ignores everything after them.
        result = {"matches": [{"id": i, **MITRE[i]} for i in ids]}
        # Full-ATT&CK search only when the hand-checked table has nothing: on familiar
        # behavior its extra suggestions are noise that invites unsupported claims.
        # IDs the agent typed that the table doesn't know are always looked up.
        typed = [t for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", behavior.upper()) if t not in MITRE]
        related = ATTACK.search(behavior, k=5, exclude=set(ids)) if (not ids or typed) else []
        if related:
            result["attack_search"] = related
            result["note"] = ("attack_search lists the closest techniques in the full MITRE "
                              f"ATT&CK knowledge base (v{ATTACK.version}). They are reference, "
                              "not evidence: claim one only if the logs you examined show that "
                              "behavior. Unsupported claims are rejected.")
        return result

    def get_user_context(self, user):
        users = self.ctx.get("users", {})
        short = user.split("\\")[-1].lower()  # "THESHIRE\pgustavo" -> "pgustavo"
        if short in users:
            return users[short]
        return {"note": "User not in directory", "directory_note": self.ctx.get("directory_note",
                "Assume a normal employee who uses only their own workstation.")}

    def decode_command(self, command):
        """Decode a PowerShell -enc/-EncodedCommand payload and flag what it does.
        Attackers base64-encode commands so scanners can't read them — this undoes that."""
        # The agent usually passes a truncated or re-typed command: look up the full one in
        # the logs using the longest base64-looking chunk (spacing differences don't matter)
        snippet = command.replace("…[truncated]", "").strip()
        chunks = re.findall(r"[A-Za-z0-9+/=]{20,}", snippet)
        if chunks:
            key = max(chunks, key=len)[:60]
            hits = self.df[self.df.command_line.astype(str).str.contains(key, regex=False, na=False)]
            if len(hits):
                command = max(hits.command_line.astype(str), key=len)
                m = re.search(r"([A-Za-z0-9+/=]{20,})", command[command.find(key[:20]):])
                if m and not re.search(r"-e(?:nc|ncodedcommand|c)?\s", command, re.I):
                    command = "-enc " + m.group(1)
            elif not re.search(r"-e(?:nc|ncodedcommand|c)?\s", snippet, re.I):
                command = "-enc " + max(chunks, key=len)  # a bare base64 string was passed
        else:  # no encoded part visible (cut off early): match the start, ignoring spacing
            norm = lambda x: re.sub(r"\s+", " ", str(x)).lower()
            start = norm(snippet)[:80]
            if len(start) > 15:
                full = self.df.command_line.dropna().astype(str)
                hits = full[full.map(norm).str.contains(start, regex=False)]
                if len(hits):
                    command = max(hits, key=len)
        m = re.search(r"-e(?:nc|ncodedcommand|c)?\s+([A-Za-z0-9+/=]{20,})", command, re.I)
        if not m:
            return {"error": "No encoded PowerShell (-enc <base64>) found in that text"}
        b64 = m.group(1)
        b64 = b64[: len(b64) - len(b64) % 4]  # a cut-off string still decodes up to the cut
        try:
            text = base64.b64decode(b64).decode("utf-16-le", errors="replace")
        except Exception as e:
            return {"error": f"Could not decode: {e}"}
        # Undo simple string-splitting tricks like 'Amsi'+'Utils' so keywords are visible
        joined = re.sub(r"['\"]\s*\+\s*['\"]", "", text)
        low = joined.lower()
        indicators = {
            "disables_script_block_logging": "scriptblocklogging" in low,
            "bypasses_amsi_antivirus_scan": "amsiutils" in low or "amsiinitfailed" in low,
            "downloads_from_web": "webclient" in low or "downloaddata" in low or "downloadstring" in low,
            "runs_downloaded_code": bool(re.search(r"\biex\b|invoke-expression", low)),
            "contains_nested_base64": "frombase64string" in low,
            "uses_proxy_credentials": "defaultnetworkcredentials" in low,
        }
        urls = re.findall(r"https?://[^\s'\")]+", joined)
        for b64 in re.findall(r"frombase64string\(['\"]([A-Za-z0-9+/=]+)['\"]\)", joined, re.I):
            try:
                inner = base64.b64decode(b64).decode("utf-16-le", errors="ignore")
                urls += re.findall(r"https?://[^\s'\")]+", inner)
            except Exception:
                pass
        # What the decoded evidence itself proves, in ATT&CK terms
        techniques = ["T1059.001", "T1027"]  # PowerShell, with a deliberately hidden command
        if indicators["disables_script_block_logging"] or indicators["bypasses_amsi_antivirus_scan"]:
            techniques.append("T1562.001")  # impairs defenses
        if indicators["downloads_from_web"]:
            techniques.append("T1105")  # pulls in more attack code
        return {"decoded_length": len(joined),
                "indicators": {k: v for k, v in indicators.items() if v},
                "techniques_shown_by_this_evidence": techniques,
                "urls_contacted": sorted(set(urls)),
                "decoded_preview": joined[:700]}

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
        "description": "Search security logs. Filters combine with AND. `source` is one of: "
                       "auth (logons), firewall, network, process, service, process_access "
                       "(a program opening another, e.g. lsass.exe) (or 'other' for "
                       "low-level background events, hidden by default). `text` searches every "
                       "field (users, IPs, commands, service names). Long fields are truncated.",
        "parameters": {"type": "object", "properties": {
            "user": {"type": "string"}, "host": {"type": "string"},
            "ip": {"type": "string", "description": "matches source or destination IP"},
            "source": {"type": "string"},
            "text": {"type": "string", "description": "e.g. 'powershell' or 'whoami'"},
            "start": {"type": "string", "description": "ISO time, e.g. 2026-10-01T02:00:00"},
            "end": {"type": "string"},
            "limit": {"type": "integer", "default": 25}}}}},
    {"type": "function", "function": {
        "name": "ip_reputation",
        "description": "Check an IP: threat-intel verdict, or whether it is inside the "
                       "company's known network ranges.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}},
                       "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "mitre_lookup",
        "description": "Map a behavior description (e.g. 'lateral movement', 'encoded "
                       "powershell', 'new service') or technique ID to MITRE ATT&CK. Put "
                       "several behaviors in ONE call; limited to 3 calls per alert.",
        "parameters": {"type": "object", "properties": {"behavior": {"type": "string"}},
                       "required": ["behavior"]}}},
    {"type": "function", "function": {
        "name": "get_user_context",
        "description": "Get a user's role and normal hosts from the company directory. "
                       "Use this to judge if activity is unusual FOR THIS PERSON.",
        "parameters": {"type": "object", "properties": {"user": {"type": "string"}},
                       "required": ["user"]}}},
    {"type": "function", "function": {
        "name": "decode_command",
        "description": "Decode an encoded PowerShell command (-enc <base64>) and report what "
                       "it does: disabling security logging, downloading code, URLs contacted. "
                       "Pass the command line (truncated text is fine).",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}},
                       "required": ["command"]}}},
]


# ---------------------------------------------------------------- plain-English step summaries
def summarize_step(name: str, args: dict, result: str) -> str:
    """One readable line describing what a tool call found — shown in the dashboard's
    investigation trail instead of raw JSON. Works on full or truncated results."""
    try:
        r = json.loads(result)
    except Exception:
        r = {}
    def first(pattern, default=""):
        m = re.search(pattern, result)
        return m.group(1) if m else default
    if r.get("error") or '"error"' in result[:20]:
        return "Tool refused: " + str(r.get("error") or first(r'"error": "([^"]+)')).split(".")[0]
    if name == "query_logs":
        filt = ", ".join(f"{k} {v}" for k, v in args.items() if k in ("user", "host", "ip", "source", "text") and v)
        n = r.get("total_matches", first(r'"total_matches": (\d+)', "?"))
        return f"{n} matching event{'' if str(n) == '1' else 's'}" + (f" ({filt})" if filt else "")
    if name == "decode_command":
        ind = r.get("indicators") or {k: True for k in re.findall(r'"(\w+)": true', result)}
        words = {"disables_script_block_logging": "disables security logging",
                 "bypasses_amsi_antivirus_scan": "bypasses antivirus (AMSI)",
                 "downloads_from_web": "downloads code", "runs_downloaded_code": "runs it",
                 "uses_proxy_credentials": "uses proxy credentials",
                 "contains_nested_base64": "hides more encoded data"}
        found = [words[k] for k in ind if k in words]
        urls = r.get("urls_contacted") or re.findall(r"https?://[\w.:/-]+", result)
        return ("Hidden command " + (", ".join(found) if found else "decoded")
                + (f"; contacts {', '.join(urls[:2])}" if urls else ""))
    if name == "ip_reputation":
        verdict = r.get("verdict", first(r'"verdict": "([^"]+)', "?"))
        note = r.get("note") or ", ".join(r.get("tags", []))
        return f"{args.get('ip')} is {verdict}" + (f": {note}" if note else "")
    if name == "get_user_context":
        if r.get("role"):
            hosts = r.get("normal_hosts")
            return f"{args.get('user')}: {r['role']}" + (f", normally uses {', '.join(hosts)}"
                                                        if isinstance(hosts, list) else "")
        return f"{args.get('user')} is not in the company directory"
    if name == "mitre_lookup":
        ids = [m["id"] for m in r.get("matches", [])] if isinstance(r.get("matches"), list) \
            else re.findall(r'"id": "(T[\d.]+)"', result)
        if isinstance(r.get("matches"), list):
            ids = [m["id"] for m in r["matches"]]
            near = [m["id"] for m in r.get("attack_search", [])]
        else:  # truncated preview: matches come first in the text
            head, _, tail = result.partition('"attack_search"')
            ids, near = re.findall(r'"id": "(T[\d.]+)"', head), re.findall(r'"id": "(T[\d.]+)"', tail)
        out = ("Matched " + ", ".join(f"{i} {technique_name(i)}".strip() for i in ids[:3])
               if ids else "No direct technique match")
        if near:
            out += "; full ATT&CK search suggests " + ", ".join(
                f"{i} {technique_name(i)}".strip() for i in near[:2])
        return out
    return result[:120]
