"""
STEP 7 — The dashboard: a web page that shows your agent working, live.

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

from src import detect
from src.agent import MockModel, NIMModel, investigate
from src.tools import MITRE, Toolbox

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports" / "incidents.json"
load_dotenv(ROOT / ".env")

st.set_page_config(page_title="SOC Agent", page_icon="🛡️", layout="wide")

SEV_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray"}
VERDICT_LABEL = {"true_positive": ":red[● Confirmed attack]",
                 "false_positive": ":green[● False alarm]",
                 "needs_review": ":orange[● Needs human review]"}


# ---------------------------------------------------------------- data
@st.cache_data  # run detection once, not on every click
def load_everything():
    df = detect.load_logs()
    t0 = time.perf_counter()
    alerts = detect.run_all(df)
    return df, alerts, time.perf_counter() - t0


df, alerts, detect_secs = load_everything()
ss = st.session_state
ss.setdefault("reports", {})     # alert_id -> report
ss.setdefault("decisions", {})   # "ALERT-001:0" -> "approved" / "rejected"


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("🛡️ Control panel")
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
    if REPORTS.exists() and st.button("📂 Load last saved run", use_container_width=True):
        ss.reports = {r["alert_id"]: r for r in json.loads(REPORTS.read_text())}
        ss.decisions = {}
    if ss.reports and st.button("Clear results", use_container_width=True):
        ss.reports, ss.decisions = {}, {}
        st.rerun()
    st.divider()
    st.caption("Tip for demos: run once with Nemotron, then use **Load last saved run** "
               "so you never wait on the API while presenting.")


# ---------------------------------------------------------------- header + KPIs
st.title("SOC Agent")
st.caption("Fast detection finds the suspicious activity. A Nemotron agent investigates "
           "each alert like a human analyst.")

reports = [ss.reports[a["id"]] for a in alerts if a["id"] in ss.reports]
confirmed = [r for r in reports if r.get("verdict") == "true_positive"]
truth = json.loads((ROOT / "data" / "ground_truth.json").read_text())
expected = {t for s in truth for t in s["mitre"]}
found = {t for r in confirmed for t in r.get("mitre", [])}
avg_secs = (sum(r.get("seconds", 0) for r in reports) / len(reports)) if reports else None

k = st.columns(5)
k[0].metric("Events scanned", f"{len(df):,}", f"in {detect_secs:.2f}s", delta_color="off")
k[1].metric("Alerts raised", len(alerts))
k[2].metric("Confirmed attacks", len(confirmed) if reports else "—")
k[3].metric("MITRE coverage", f"{len(found & expected)}/{len(expected)}" if reports else "—")
k[4].metric("Avg triage time", f"{avg_secs:.0f}s" if avg_secs else "—",
            "vs ~15 min manual" if avg_secs else None, delta_color="off")


# ---------------------------------------------------------------- activity chart
st.subheader("Activity over the day")
bins = df.assign(
    bucket=df.timestamp.dt.floor("30min"),
    kind=df.apply(lambda r: "Failed logins" if r.get("outcome") == "failure"
                  else ("Logins" if r["source"] == "auth" else "Network traffic"), axis=1))
pivot = bins.pivot_table(index="bucket", columns="kind", values="source",
                         aggfunc="count", fill_value=0)
st.bar_chart(pivot, height=220, color=["#e5484d", "#3e63dd", "#8b8d98"][:len(pivot.columns)])
st.caption("The red spike around 2 AM is the brute-force attack. Can you spot it without the agent?")


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
                report = investigate(alert, Toolbox(df), model, prior=prior,
                                     verbose=False, on_step=show_step)
            except Exception as e:
                status.update(label=f"{alert['id']} failed: {e}", state="error")
                st.stop()
            report["seconds"] = round(time.perf_counter() - t0, 1)
            prior.append(report)
            ss.reports[alert["id"]] = report
            status.update(label=f"{alert['id']} → {report.get('title', report.get('verdict'))}",
                          state="complete", expanded=False)
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
