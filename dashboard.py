"""
STEP 7 — The GHOST dashboard: a web page that shows your agent working, live.

Streamlit turns a Python script into a web page. Each st.something() call
draws one element on the page (a title, a chart, a button...). When you click
a button, Streamlit re-runs this whole script from top to bottom. Anything
that must survive those re-runs (like finished reports) lives in
st.session_state, which is a dictionary that persists between clicks.

Run:   streamlit run dashboard.py
Then open the link it prints (usually http://localhost:8501).
"""
import json
import os
import time
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src import detect, scenarios
from src.agent import MockModel, NIMModel, investigate
from src.tools import MITRE, Toolbox

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

st.set_page_config(page_title="GHOST", page_icon="👻", layout="wide")

SEV_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray"}
VERDICT_LABEL = {"true_positive": ":red[● Confirmed attack]",
                 "false_positive": ":green[● False alarm]",
                 "needs_review": ":orange[● Needs human review]"}
# Chart categories, in drawing order, with their colors
KINDS = {"Failed logins": "#e5484d", "Logins": "#3e63dd", "Programs & services": "#f5a623",
         "Network traffic": "#8b8d98", "Background (Windows)": "#3a3c44"}


# ---------------------------------------------------------------- data
@st.cache_data  # run detection once per scenario, not on every click
def load_everything(scenario: str):
    df = detect.load_logs(scenarios.path(scenario) / "logs.jsonl")
    t0 = time.perf_counter()
    alerts = detect.run_all(df)
    return df, alerts, time.perf_counter() - t0


ss = st.session_state
ss.setdefault("reports", {})     # alert_id -> report
ss.setdefault("decisions", {})   # "ALERT-001:0" -> "approved" / "rejected"


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("👻 GHOST control panel")
    names = scenarios.list_scenarios()
    scenario = st.selectbox("Scenario", names,
                            format_func=lambda n: scenarios.load_context(n).get("title", n))
    if ss.get("scenario") != scenario:  # switching scenario clears old results
        ss.scenario, ss.reports, ss.decisions = scenario, {}, {}
    mode = st.radio("Detective", ["Practice (scripted)", "Nemotron (real AI)"],
                    help="Practice mode needs no API key. Real AI uses your NVIDIA key from .env.")
    has_key = bool(os.environ.get("NVIDIA_API_KEY", "").startswith("nvapi-")
                   and "your-key" not in os.environ.get("NVIDIA_API_KEY", ""))
    if mode.startswith("Nemotron"):
        st.caption(f"Model: `{os.environ.get('NIM_MODEL', 'not set')}`")
        if not has_key:
            st.error("No NVIDIA key found in .env")
    run = st.button("▶ Run live investigation", type="primary", use_container_width=True,
                    disabled=mode.startswith("Nemotron") and not has_key)
    REPORTS = ROOT / "reports" / f"incidents_{scenario}.json"
    if REPORTS.exists() and st.button("📂 Load last saved run", use_container_width=True):
        ss.reports = {r["alert_id"]: r for r in json.loads(REPORTS.read_text())}
        ss.decisions = {}
    if ss.reports and st.button("Clear results", use_container_width=True):
        ss.reports, ss.decisions = {}, {}
        st.rerun()
    st.divider()
    st.caption("Tip for demos: run once with Nemotron, then use **Load last saved run** "
               "so you never wait on the API while presenting.")

df, alerts, detect_secs = load_everything(scenario)
ctx = scenarios.load_context(scenario)


# ---------------------------------------------------------------- header + KPIs
st.title("👻 GHOST")
st.caption("Generative Hunting & Operations Security Toolkit · fast detection finds the "
           "suspicious activity, a Nemotron agent investigates each alert like a human analyst.")
with st.container(border=True):
    st.markdown(f"**{ctx.get('title', scenario)}**  \n{ctx.get('description', '')}")
    if ctx.get("source_url"):
        st.caption(f"Data source: {ctx['source_url']} · dataset {ctx.get('otrf_id', '')}")

reports = [ss.reports[a["id"]] for a in alerts if a["id"] in ss.reports]
confirmed = [r for r in reports if r.get("verdict") == "true_positive"]
found = {t for r in confirmed for t in r.get("mitre", [])}
expected, hit = scenarios.technique_recall(scenarios.load_truth(scenario), found)
avg_secs = (sum(r.get("seconds", 0) for r in reports) / len(reports)) if reports else None

k = st.columns(5)
k[0].metric("Events scanned", f"{len(df):,}", f"in {detect_secs:.2f}s", delta_color="off")
k[1].metric("Alerts raised", len(alerts))
k[2].metric("Confirmed attacks", len(confirmed) if reports else "—")
k[3].metric("Answer-key coverage", f"{len(hit)}/{len(expected)}" if reports else "—",
            help="MITRE techniques in the scenario's answer key that the agent identified. "
                 "A sub-technique (T1021.002) counts for its parent (T1021).")
k[4].metric("Avg triage time", f"{avg_secs:.0f}s" if avg_secs else "—",
            "vs ~15 min manual (estimate)" if avg_secs else None, delta_color="off")


# ---------------------------------------------------------------- activity chart
def kind(r):
    if r["source"] == "auth":
        return "Failed logins" if r.get("outcome") == "failure" else "Logins"
    if r["source"] in ("process", "service"):
        return "Programs & services"
    if r["source"] in ("network", "firewall"):
        return "Network traffic"
    return "Background (Windows)"


span = (df.timestamp.max() - df.timestamp.min()).total_seconds()
freq = "30min" if span > 6 * 3600 else "5min" if span > 3600 else "1min" if span > 900 else "5s"
st.subheader("Activity timeline")
pivot = (df.assign(bucket=df.timestamp.dt.floor(freq), kind=df.apply(kind, axis=1))
         .pivot_table(index="bucket", columns="kind", values="source", aggfunc="count",
                      fill_value=0))
cols = [c for c in KINDS if c in pivot.columns]
st.bar_chart(pivot[cols], height=220, color=[KINDS[c] for c in cols])
st.caption(ctx.get("chart_note", "") + " Can you spot the attack without the agent?")


# ---------------------------------------------------------------- live run
def run_live():
    prior = []
    for alert in alerts:
        model = MockModel() if mode.startswith("Practice") else NIMModel()
        with st.status(f"🔎 Investigating {alert['id']}: {alert['summary']}",
                       expanded=True) as status:
            def show_step(t):
                st.write(f"**Step {t['step']}** · `{t['tool']}` {t['args']}")
                if mode.startswith("Practice"):
                    time.sleep(0.5)  # slow the scripted run down so you can watch it
            t0 = time.perf_counter()
            try:
                report = investigate(alert, Toolbox(df, ctx), model, prior=prior,
                                     verbose=False, on_step=show_step)
            except Exception as e:
                status.update(label=f"{alert['id']} failed: {e}", state="error")
                st.stop()
            report["seconds"] = round(time.perf_counter() - t0, 1)
            prior.append(report)
            ss.reports[alert["id"]] = report
            status.update(label=f"{alert['id']} → {report.get('title', report.get('verdict'))}",
                          state="complete", expanded=False)
    for r in prior:
        for t in r.get("trace", []):
            t.pop("result_full", None)
    REPORTS.parent.mkdir(exist_ok=True)
    REPORTS.write_text(json.dumps(prior, indent=2))


if run:
    ss.reports, ss.decisions = {}, {}
    st.subheader("Live investigation")
    run_live()
    st.rerun()  # redraw the page with the finished results


# ---------------------------------------------------------------- attack chain
if confirmed:
    st.subheader("Reconstructed attack chain")
    cols = st.columns(len(confirmed) * 2 - 1)
    for i, r in enumerate(confirmed):
        with cols[i * 2]:
            with st.container(border=True):
                st.markdown(f"**{i + 1}. {r.get('title', r['alert_id'])}**")
                st.caption(" · ".join(f"{t} {MITRE.get(t, {}).get('name', '')}"
                                      for t in r.get("mitre", [])))
        if i < len(confirmed) - 1:
            cols[i * 2 + 1].markdown("<h2 style='text-align:center;margin-top:12px'>→</h2>",
                                     unsafe_allow_html=True)


# ---------------------------------------------------------------- alert cards
st.subheader("Alerts")
if not reports and not run:
    st.info("Press **▶ Run live investigation** in the sidebar to watch the agent work.")

benign = {b["alert_id"]: b for b in scenarios.benign_results(
    scenarios.load_truth(scenario), alerts, ss.reports)}

for a in alerts:
    r = ss.reports.get(a["id"])
    with st.container(border=True):
        top = st.columns([5, 2])
        sev = a["severity"]
        top[0].markdown(f":{SEV_COLOR.get(sev, 'gray')}-background[{sev.upper()}] "
                        f"**{a['id']}** · {a['type'].replace('_', ' ')}  \n{a['summary']}")
        if not r:
            top[1].caption("Not investigated yet")
            continue
        top[1].markdown(VERDICT_LABEL.get(r.get("verdict"), r.get("verdict", "")))
        conf = r.get("confidence")
        if isinstance(conf, (int, float)):
            top[1].progress(min(int(conf), 100) / 100, text=f"Confidence {conf}%")

        if a["id"] in benign:
            b = benign[a["id"]]
            (st.success if b["correct"] else st.error)(
                f"Answer key: legitimate activity. {b['note']} — GHOST said "
                f"**{r.get('verdict')}** ({'correct' if b['correct'] else 'wrong'})")
        st.markdown(f"**{r.get('title', '')}**")
        st.write(r.get("summary", r.get("raw", "")))
        if r.get("related_to_prior"):
            st.caption(f"🔗 Linked to earlier alerts: {r['related_to_prior']}")

        left, right = st.columns(2)
        with left:
            st.markdown("**Evidence**")
            for e in r.get("evidence", []):
                st.markdown(f"- {e}")
            if r.get("mitre"):
                st.markdown("**MITRE ATT&CK**  \n" + "  ".join(
                    f"`{t}` {MITRE.get(t, {}).get('name', '')}" for t in r["mitre"]))
            if r.get("unverified_mitre"):
                st.caption("⚠️ Rejected by grounding check (claimed without evidence): "
                           + ", ".join(r["unverified_mitre"]))
        with right:
            st.markdown("**Recommended actions** · a human must approve")
            for i, act in enumerate(r.get("recommended_actions", [])):
                key = f"{a['id']}:{i}"
                row = st.columns([4, 1, 1])
                label = act.get("action", str(act)) if isinstance(act, dict) else str(act)
                target = act.get("target", "") if isinstance(act, dict) else ""
                decision = ss.decisions.get(key)
                mark = {"approved": "✅ ", "rejected": "❌ "}.get(decision, "")
                row[0].markdown(f"{mark}{label}" + (f" → `{target}`" if target else ""))
                if not decision:
                    if row[1].button("Approve", key=f"ok-{key}"):
                        ss.decisions[key] = "approved"
                        st.rerun()
                    if row[2].button("Reject", key=f"no-{key}"):
                        ss.decisions[key] = "rejected"
                        st.rerun()

        with st.expander(f"Investigation trace · {len(r.get('trace', []))} tool calls · "
                         f"{r.get('seconds', '?')}s"):
            for t in r.get("trace", []):
                st.markdown(f"**Step {t['step']}** · `{t['tool']}`  {t['args']}")
                st.code(t["result_preview"], language="json", wrap_lines=True)
