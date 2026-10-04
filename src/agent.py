"""
STEP 5 — The agent: Nemotron investigates each alert using the tools.

This is the "agent loop", the core pattern behind almost every AI agent:

    while not done:
        ask the model what to do next
        if it wants a tool -> run it, append the result, loop again
        if it gives a final answer -> stop

NIM (NVIDIA Inference Microservices) exposes an OpenAI-compatible API, so we
use the standard `openai` Python library and just point it at NVIDIA:
  - Hosted (free tier, easiest): base_url = https://integrate.api.nvidia.com/v1
  - Self-hosted NIM on a Nebius GPU: base_url = http://<your-server>:8000/v1
Switching between them is a one-line config change — great demo talking point.

MOCK MODE: `--mock` uses a scripted fake model so you can run and understand
the whole pipeline before you have an API key. Read MockModel to see exactly
what a real model's tool calls look like.
"""
import json
import os
import re

from .tools import TOOL_SCHEMAS, Toolbox, summarize_step

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst.
You receive one alert at a time and must investigate it using your tools before
concluding. Work like a careful human analyst:

1. Gather evidence with query_logs (look before and after the alert time).
   On Windows hosts, follow the process chain: which parent launched what.
2. If you see an encoded command (-enc / -EncodedCommand), ALWAYS run
   decode_command on it — the hidden content is often the strongest evidence.
3. Check every IP that isn't the local machine with ip_reputation.
4. Use get_user_context to judge whether behavior is unusual for that person.
5. Map the behavior to MITRE ATT&CK with mitre_lookup.
   Not every alert is an attack: legitimate software (backup, antivirus, cloud and
   diagnostics agents) can trip detectors. If the evidence shows legitimate activity,
   say false_positive — a wrong "attack" verdict wastes analysts' time too.
6. Connect this alert to any earlier findings you are given (attack chains matter).

ATT&CK guidance:
- Alerts include rule_tags: the techniques the detection rule was written to catch.
  Treat them as hypotheses. Keep the ones your evidence confirms, drop the rest,
  and add any other techniques you find.
- If an attacker successfully logged in with a real user's password, include
  T1078 (Valid Accounts) in addition to the technique they used to get it.
- Call mitre_lookup at most twice per alert (several behaviors per call), then decide.
- You have a limited number of steps. Stop investigating once the evidence is clear.

Never invent evidence. Only cite facts your tools returned.
Containment actions are RECOMMENDATIONS that a human must approve.

When finished, reply with ONLY a JSON object:
{"verdict": "true_positive" | "false_positive" | "needs_review",
 "confidence": 0-100,
 "title": "short incident title",
 "summary": "2-3 sentences in plain English",
 "mitre": ["T1110", ...],
 "evidence": ["fact from a tool result", ...],
 "related_to_prior": "how this links to earlier alerts, or null",
 "recommended_actions": [{"action": "...", "target": "...", "priority": "immediate|soon|later"}]}"""

MAX_STEPS = 10  # safety limit so a confused model can't loop forever


# --------------------------------------------------------------------------
# Talking to the model
# --------------------------------------------------------------------------
class NIMModel:
    """Real model via NVIDIA NIM (OpenAI-compatible API)."""

    def __init__(self):
        from openai import OpenAI  # imported here so --mock works without the package
        key = os.environ.get("NVIDIA_API_KEY")
        if not key:
            raise SystemExit("Set NVIDIA_API_KEY in .env (get one free at build.nvidia.com), "
                             "or run with --mock")
        self.client = OpenAI(
            base_url=os.environ.get("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            api_key=key)
        self.model = os.environ.get("NIM_MODEL", "nvidia/nemotron-3-super-120b-a12b")

    def step(self, messages: list[dict], allow_tools: bool = True) -> dict:
        extra = {"tools": TOOL_SCHEMAS, "tool_choice": "auto"} if allow_tools else {}
        resp = self.client.chat.completions.create(
            model=self.model, messages=messages, temperature=0.2, max_tokens=8192, **extra)
        msg = resp.choices[0].message
        return {"content": msg.content or "",
                "tool_calls": [{"id": tc.id, "name": tc.function.name,
                                "arguments": json.loads(tc.function.arguments or "{}")}
                               for tc in (msg.tool_calls or [])]}


class MockModel:
    """Scripted stand-in for Nemotron. It returns the SAME shape a real model
    returns: either tool calls or a final text answer."""

    def __init__(self):
        self.turn = 0

    def step(self, messages: list[dict], allow_tools: bool = True) -> dict:
        if not allow_tools:
            self.turn = 99  # skip to final answer
        alert = json.loads(messages[1]["content"].split("ALERT:\n", 1)[1].split("\n\n")[0])
        plans = {
            "brute_force": [("query_logs", {"ip": alert.get("src_ip"), "limit": 5}),
                            ("ip_reputation", {"ip": alert.get("src_ip")}),
                            ("get_user_context", {"user": alert.get("user")}),
                            ("mitre_lookup", {"behavior": "brute force valid account"})],
            "lateral_movement": [("query_logs", {"user": alert.get("user"), "limit": 10}),
                                 ("get_user_context", {"user": alert.get("user")}),
                                 ("mitre_lookup", {"behavior": "lateral movement"})],
            "exfiltration": [("query_logs", {"ip": alert.get("dst_ip"), "limit": 6}),
                             ("ip_reputation", {"ip": alert.get("dst_ip")}),
                             ("mitre_lookup", {"behavior": "exfiltration"})],
            "remote_service_execution": [
                ("query_logs", {"host": alert.get("host"), "source": "service"}),
                ("ip_reputation", {"ip": alert.get("src_ip") or ""}),
                ("get_user_context", {"user": alert.get("user") or ""}),
                ("mitre_lookup", {"behavior": "psexec new service service execution"})],
            "encoded_powershell": [
                ("query_logs", {"host": alert.get("host"), "source": "process"}),
                ("decode_command", {"command": "powershell  -noP -sta -w 1 -enc"}),
                ("mitre_lookup", {"behavior": "encoded powershell amsi"})],
            "remote_wmi_execution": [
                ("query_logs", {"host": alert.get("host"), "source": "process"}),
                ("get_user_context", {"user": alert.get("user") or ""}),
                ("mitre_lookup", {"behavior": "wmi remote execution"})],
            "lsass_memory_access": [
                ("query_logs", {"host": alert.get("host"), "source": "process_access"}),
                ("mitre_lookup", {"behavior": "lsass credential dump"})],
            "script_c2_beacon": [
                ("query_logs", {"ip": alert.get("dst_ip")}),
                ("ip_reputation", {"ip": alert.get("dst_ip")}),
                ("mitre_lookup", {"behavior": "c2 beacon download"})],
        }.get(alert["type"], [("query_logs", {"host": alert.get("host")})])
        if self.turn < len(plans):
            name, args = plans[self.turn]
            self.turn += 1
            return {"content": "", "tool_calls": [{"id": f"call_{self.turn}",
                                                   "name": name, "arguments": args}]}
        mitre = {"brute_force": ["T1110", "T1078"], "lateral_movement": ["T1021"],
                 "exfiltration": ["T1048"],
                 "remote_service_execution": ["T1021.002", "T1543.003", "T1569.002"],
                 "encoded_powershell": ["T1059.001", "T1027", "T1562.001"],
                 "script_c2_beacon": ["T1071.001", "T1105"],
                 "remote_wmi_execution": ["T1047"],
                 "lsass_memory_access": ["T1003.001"]}.get(alert["type"], [])
        return {"content": json.dumps({
            "verdict": "needs_review" if alert.get("severity") == "medium" else "true_positive",
            "confidence": 90,
            "title": f"[MOCK] {alert['type'].replace('_', ' ').title()}",
            "summary": f"[MOCK] {alert['summary']}. Replace --mock with a real API key to "
                       f"see Nemotron reason over the tool results.",
            "mitre": mitre, "evidence": [alert["summary"]],
            "related_to_prior": "See earlier alerts" if "PRIOR FINDINGS" in messages[1]["content"]
                                and "none yet" not in messages[1]["content"] else None,
            "recommended_actions": [{"action": "Escalate to on-call analyst",
                                     "target": alert.get("host") or alert.get("user"),
                                     "priority": "immediate"}]}), "tool_calls": []}


# --------------------------------------------------------------------------
# The agent loop
# --------------------------------------------------------------------------
def parse_report(text: str) -> tuple[dict | None, str | None]:
    """Models sometimes wrap JSON in prose or ```fences```. Grab the {...} part.
    Returns (report, None) on success or (None, error message) on failure."""
    match = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not match:
        return None, "No JSON object found. You wrote prose instead of the report."
    try:
        report = json.loads(match.group(0))
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e.msg} at character {e.pos}."
    if report.get("verdict") not in ("true_positive", "false_positive", "needs_review"):
        return None, "The 'verdict' field must be true_positive, false_positive or needs_review."
    return report, None


def finalize(reply_text: str, messages: list[dict], model) -> dict:
    """SELF-CORRECTION: if the report can't be read, show the model its own mistake
    and let it fix it once — instead of throwing away a good investigation."""
    report, error = parse_report(reply_text)
    if report is not None:
        return report
    messages.append({"role": "assistant", "content": reply_text or ""})
    messages.append({"role": "user", "content": f"Your final report could not be read: {error} "
                     "Reply with ONLY the corrected JSON object, nothing else."})
    retry = model.step(messages, allow_tools=False)
    report, error = parse_report(retry["content"])
    if report is not None:
        report["self_corrected"] = True
        return report
    return {"verdict": "needs_review", "summary": f"Report unreadable after retry ({error})",
            "raw": (retry["content"] or reply_text or "")[:2000]}


TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def ground_mitre(report: dict, alert: dict, trace: list[dict]) -> dict:
    """GROUNDING CHECK: the model may only claim techniques it actually saw this
    investigation — in the alert's rule tags or in a tool result. Anything else is
    probably recalled from memory (a hallucination), so it is set aside as
    'unverified' and doesn't count toward the score."""
    seen = set(alert.get("rule_tags", []))
    seen |= set(TECHNIQUE_ID.findall(SYSTEM_PROMPT))  # techniques our own guidance names
    for t in trace:
        seen |= set(TECHNIQUE_ID.findall(t.get("result_full", t.get("result_preview", ""))))
    seen |= {t.split(".")[0] for t in seen}  # a confirmed T1059.001 supports its parent T1059
    claimed = [m.strip() for m in report.get("mitre", []) if isinstance(m, str)]
    report["mitre"] = [m for m in claimed if m in seen]
    unverified = [m for m in claimed if m not in seen]
    if unverified:
        report["unverified_mitre"] = unverified
    return report


def investigate(alert: dict, toolbox: Toolbox, model, prior: list[dict], verbose=True,
                on_step=None) -> dict:
    """on_step: optional function called after every tool call — the dashboard uses
    it to show the investigation live, step by step."""
    prior_text = "\n".join(f"- {p['alert_id']}: {p.get('title')} ({p.get('verdict')})"
                           for p in prior) or "none yet"
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"ALERT:\n{json.dumps(alert)}\n\nPRIOR FINDINGS:\n{prior_text}"},
    ]
    trace = []  # every step the agent took — this powers the dashboard timeline later
    toolbox.reset()

    for step in range(1, MAX_STEPS + 1):
        last = step == MAX_STEPS
        if last:  # out of steps: make it conclude with what it has, instead of failing
            messages.append({"role": "user", "content": "Step limit reached. Write your final "
                             "JSON report now using only the evidence gathered so far."})
        reply = model.step(messages, allow_tools=not last)

        if not reply["tool_calls"]:  # no more tools -> this is the final answer
            report = finalize(reply["content"], messages, model)
            report = ground_mitre(report, alert, trace)
            report.update({"alert_id": alert["id"], "steps": step, "trace": trace})
            return report

        # Record what the model asked for, in the OpenAI message format
        messages.append({"role": "assistant", "content": reply["content"], "tool_calls": [
            {"id": tc["id"], "type": "function",
             "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}}
            for tc in reply["tool_calls"]]})

        for tc in reply["tool_calls"]:
            result = toolbox.run(tc["name"], tc["arguments"])
            if verbose:
                print(f"    step {step}: {tc['name']}({tc['arguments']}) -> {result[:90]}...")
            trace.append({"step": step, "tool": tc["name"], "args": tc["arguments"],
                          "result_preview": result[:300], "result_full": result,
                          "summary": summarize_step(tc["name"], tc["arguments"], result)})
            if on_step:
                on_step(trace[-1])
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})

    return {"alert_id": alert["id"], "verdict": "needs_review",
            "summary": "Hit step limit without a conclusion", "trace": trace}
