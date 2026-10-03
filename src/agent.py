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

from .tools import TOOL_SCHEMAS, Toolbox

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst.
You receive one alert at a time and must investigate it using your tools before
concluding. Work like a careful human analyst:

1. Gather evidence with query_logs (look before and after the alert time).
2. Check every external IP with ip_reputation.
3. Use get_user_context to judge whether behavior is unusual for that person.
4. Map the behavior to MITRE ATT&CK with mitre_lookup.
5. Connect this alert to any earlier findings you are given (attack chains matter).

ATT&CK tips: if an attacker successfully logged in with a real user's password,
include T1078 (Valid Accounts) in addition to the technique they used to get it.
Call mitre_lookup at most twice per alert, then decide.

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
        }[alert["type"]]
        if self.turn < len(plans):
            name, args = plans[self.turn]
            self.turn += 1
            return {"content": "", "tool_calls": [{"id": f"call_{self.turn}",
                                                   "name": name, "arguments": args}]}
        mitre = {"brute_force": ["T1110", "T1078"], "lateral_movement": ["T1021"],
                 "exfiltration": ["T1048"]}[alert["type"]]
        return {"content": json.dumps({
            "verdict": "true_positive", "confidence": 90,
            "title": f"[MOCK] {alert['type'].replace('_', ' ').title()}",
            "summary": f"[MOCK] {alert['summary']}. Replace --mock with a real API key to "
                       f"see Nemotron reason over the tool results.",
            "mitre": mitre, "evidence": [alert["summary"]],
            "related_to_prior": "See earlier alerts" if "PRIOR FINDINGS" in messages[1]["content"]
                                and "none yet" not in messages[1]["content"] else None,
            "recommended_actions": [{"action": "Escalate to on-call analyst",
                                     "target": alert.get("user") or alert.get("host"),
                                     "priority": "immediate"}]}), "tool_calls": []}


# --------------------------------------------------------------------------
# The agent loop
# --------------------------------------------------------------------------
def parse_report(text: str) -> dict:
    """Models sometimes wrap JSON in prose or ```fences```. Grab the {...} part."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    try:
        return json.loads(match.group(0)) if match else {"verdict": "needs_review", "raw": text}
    except json.JSONDecodeError:
        return {"verdict": "needs_review", "raw": text}


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

    for step in range(1, MAX_STEPS + 1):
        last = step == MAX_STEPS
        if last:  # out of steps: make it conclude with what it has, instead of failing
            messages.append({"role": "user", "content": "Step limit reached. Write your final "
                             "JSON report now using only the evidence gathered so far."})
        reply = model.step(messages, allow_tools=not last)

        if not reply["tool_calls"]:  # no more tools -> this is the final answer
            report = parse_report(reply["content"])
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
                          "result_preview": result[:300]})
            if on_step:
                on_step(trace[-1])
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})

    return {"alert_id": alert["id"], "verdict": "needs_review",
            "summary": "Hit step limit without a conclusion", "trace": trace}
