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
import threading
import time
from datetime import date
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src import detect, ingest, scenarios
from src.agent import MockModel, NIMModel, investigate, provider
from src.tools import Toolbox, summarize_step, technique_name

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

# On Streamlit Community Cloud there is no .env file: the key lives in the app's
# private "Secrets" settings instead. Copy those into the environment so the rest
# of GHOST reads them exactly like a local .env. (Locally there are no secrets.)
SECRET_KEYS = ("NEBIUS_API_KEY", "NVIDIA_API_KEY", "NIM_BASE_URL", "NIM_MODEL",
               "GHOST_PUBLIC", "GHOST_SESSION_LIVE_RUNS", "GHOST_DAILY_LIVE_RUNS")
try:
    for k in SECRET_KEYS:
        if k in st.secrets and not os.environ.get(k):
            os.environ[k] = str(st.secrets[k])
except Exception:  # no secrets file: running locally with .env
    pass

# Public mode (set GHOST_PUBLIC = "1" in Secrets): visitors can run live Nemotron
# investigations, but only a few each, and their runs never replace the saved
# results that every other visitor sees first.
PUBLIC = os.environ.get("GHOST_PUBLIC") == "1"
SESSION_LIVE_MAX = int(os.environ.get("GHOST_SESSION_LIVE_RUNS", "3"))
DAILY_LIVE_MAX = int(os.environ.get("GHOST_DAILY_LIVE_RUNS", "40"))

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


UPLOAD = "__upload__"
MAX_UPLOAD_ALERTS = 5  # live runs on uploads investigate at most this many (public mode)
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@st.cache_data(max_entries=3, show_spinner="Reading your logs...")
def load_upload(name: str, data: bytes, ranges: tuple):
    df, fmt = ingest.to_events(name, data)
    t0 = time.perf_counter()
    alerts = detect.run_all(df)
    return df, alerts, time.perf_counter() - t0, ingest.context(name, len(df), fmt, list(ranges))


@st.cache_resource  # ONE counter shared by every visitor of this server
def live_budget():
    return {"day": None, "runs": 0, "lock": threading.Lock()}


def live_runs_left() -> tuple[int, str]:
    """How many live Nemotron runs this visitor may start now, and why not if zero."""
    if not PUBLIC:
        return 1, ""
    b = live_budget()
    with b["lock"]:
        if b["day"] != date.today():
            b["day"], b["runs"] = date.today(), 0
        today_left = DAILY_LIVE_MAX - b["runs"]
    mine_left = SESSION_LIVE_MAX - ss.get("live_runs", 0)
    if today_left <= 0:
        return 0, "Today's live runs are used up. Try Practice mode, or come back tomorrow."
    if mine_left <= 0:
        return 0, f"You've used your {SESSION_LIVE_MAX} live runs. Practice mode is unlimited."
    return min(today_left, mine_left), ""


def spend_live_run():
    if PUBLIC:
        b = live_budget()
        with b["lock"]:
            b["runs"] += 1
        ss.live_runs = ss.get("live_runs", 0) + 1


ss = st.session_state
ss.setdefault("reports", {})     # alert_id -> report
ss.setdefault("decisions", {})   # "ALERT-001:0" -> "approved" / "rejected"


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("👻 GHOST control panel")
    names = scenarios.list_scenarios()
    scenario = st.selectbox("Scenario", names + [UPLOAD],
                            format_func=lambda n: "📤 Upload your own logs" if n == UPLOAD
                            else scenarios.load_context(n).get("title", n))
    uploaded, ranges_text = None, ""
    if scenario == UPLOAD:
        uploaded = st.file_uploader("Log file", type=["jsonl", "json", "csv"],
                                    help="GHOST-format events, or raw Windows Security/Sysmon "
                                         "events as JSON lines. Up to 50 MB.")
        ranges_text = st.text_input("Your network ranges (optional)",
                                    placeholder="10.0.0.0/8, 192.168.1.0/24",
                                    help="Addresses inside these count as company assets. Left "
                                         "empty, GHOST says it can't tell, instead of guessing.")
    scenario_key = (f"upload:{uploaded.name}:{uploaded.size}:{ranges_text}" if uploaded
                    else scenario)
    if ss.get("scenario") != scenario_key:  # switching scenario clears old results
        ss.scenario, ss.reports, ss.decisions = scenario_key, {}, {}
    provider_name, _, key = provider()
    has_key = key is not None
    mode = st.radio("Detective", ["Practice (scripted)", "Nemotron (real AI)"],
                    index=1 if has_key else 0,
                    help="Practice replays a scripted investigation instantly, no API key. "
                         "Nemotron is the real AI investigating live.")
    blocked = ""
    if mode.startswith("Nemotron"):
        st.caption(f"Model: `{os.environ.get('NIM_MODEL', 'not set')}` via {provider_name}")
        if not has_key:
            blocked = f"No API key for {provider_name} on this server."
        else:
            left, blocked = live_runs_left()
            if PUBLIC and left:
                st.caption(f"Live runs left for you: {left}. Each takes about 20-60 seconds.")
        if blocked:
            st.warning(blocked)
    run = st.button("▶ Run live investigation", type="primary", use_container_width=True,
                    disabled=bool(blocked))
    REPORTS = None if scenario == UPLOAD else ROOT / "reports" / f"incidents_{scenario}.json"
    if REPORTS and REPORTS.exists() and st.button("📂 Load last saved run", use_container_width=True):
        ss.reports = {r["alert_id"]: r for r in json.loads(REPORTS.read_text())}
        ss.decisions, ss.showing_saved = {}, True
    if ss.reports and st.button("Clear results", use_container_width=True):
        ss.reports, ss.decisions = {}, {}
        st.rerun()
    st.divider()
    if not PUBLIC:
        st.caption("Tip for demos: run once with Nemotron, then use **Load last saved run** "
                   "so you never wait on the API while presenting.")

if scenario == UPLOAD and not uploaded:
    st.title("📤 Investigate your own logs")
    st.markdown(
        "Upload a log file in the sidebar and GHOST runs its 8 detectors on it, then Nemotron "
        "investigates each alert, exactly as with the built-in attacks.\n\n"
        "**Accepted formats** (`.jsonl`, `.json` or `.csv`, up to 50 MB):\n"
        "- **GHOST format:** one event per line with `timestamp`, `source` (auth, process, "
        "service, network, process_access) and fields like `user`, `host`, `src_ip`, `dst_ip`, "
        "`process`, `parent_process`, `command_line`.\n"
        "- **Raw Windows event logs** as JSON lines with `EventID`, `Channel`, `Hostname`, "
        "`@timestamp`: Windows Security (4624/4625 logons, 4688 processes, 4697 services), "
        "System 7045 and Sysmon 1/3/10, the way OTRF Security Datasets, Winlogbeat and many "
        "SIEM exports store them.\n\n"
        "Uploads have no answer key and no company directory, so GHOST's verdicts are its own "
        "and it tells you when it can't know something (like who owns a private IP).")
    sample = scenarios.path("real_psexec") / "logs.jsonl"
    st.download_button("⬇️ Download a sample file (real PsExec attack, GHOST format)",
                       sample.read_bytes(), file_name="ghost_sample_psexec.jsonl",
                       mime="application/json")
    st.caption("Raw Windows samples: any dataset from "
               "[OTRF Security Datasets](https://github.com/OTRF/Security-Datasets), unzipped.")
    st.stop()

truth = []
if scenario == UPLOAD:
    try:
        ranges = tuple(ingest.parse_ranges(ranges_text))
        df, alerts, detect_secs, ctx = load_upload(uploaded.name, uploaded.getvalue(), ranges)
    except ingest.UploadError as e:
        st.error(f"Couldn't use that file: {e}")
        st.stop()
else:
    df, alerts, detect_secs = load_everything(scenario)
    ctx = scenarios.load_context(scenario)
    truth = scenarios.load_truth(scenario)

# First visit to a scenario: show the saved Nemotron investigation right away,
# so visitors see real results without an API key or a wait.
if ss.get("autoloaded") != scenario and not ss.reports and REPORTS and REPORTS.exists():
    ss.reports = {r["alert_id"]: r for r in json.loads(REPORTS.read_text())}
    ss.autoloaded, ss.showing_saved = scenario, True


# ---------------------------------------------------------------- header + KPIs
st.title("👻 GHOST")
st.caption("Generative Hunting & Operations Security Toolkit · fast detection finds the "
           "suspicious activity, a Nemotron agent investigates each alert like a human analyst.")
first_visit = not ss.get("seen_howto")  # open the guide on a visitor's first page load
ss.seen_howto = True
with st.expander("🧪 How to test GHOST", expanded=first_visit):
    st.markdown(
        "1. **Look (30 seconds).** Pick a real attack in the sidebar, for example "
        "*Empire Invoke-PsExec*. Below you'll see Nemotron's saved investigation: the attack "
        "chain, each alert's verdict, evidence, MITRE ATT&CK techniques, and the step-by-step "
        "trail of what the AI did.\n"
        "2. **Watch it run (1 minute).** Choose **Nemotron (real AI)** and press "
        "**▶ Run live investigation**. Nemotron, served by Nebius Token Factory, investigates "
        "every alert in front of you. **Practice** mode replays a scripted run with no AI.\n"
        "3. **Check the false alarm.** Pick *Empire Invoke-SMBExec* and open the medium "
        "LSASS alert: it's Microsoft's Azure agent, and the green box shows GHOST called it "
        "a false positive, matching the dataset's answer key.\n"
        "4. **Bring your own logs.** Choose **📤 Upload your own logs** at the bottom of the "
        "scenario menu, download the sample file there (or use your own), upload it and press "
        "**▶ Run live investigation**.\n"
        "5. **Run it yourself.** Clone "
        "[the repo](https://github.com/Mastoor2002/soc-agent-GHOST-) and run "
        "`python -m src.main --mock` (no key needed), or "
        "`python -m src.benchmark` for detection on all 5 scenarios.")
with st.container(border=True):
    st.markdown(f"**{ctx.get('title', scenario)}**  \n{ctx.get('description', '')}")
    if ctx.get("source_url"):
        st.caption(f"Data source: {ctx['source_url']} · dataset {ctx.get('otrf_id', '')}")

if ss.get("showing_saved") and ss.reports:
    first = next(iter(ss.reports.values()))
    who = first.get("model") or "NVIDIA Nemotron"
    via = f" via {first['provider']}" if first.get("provider") else ""
    when = f", run on {first['run_date']}" if first.get("run_date") else ""
    st.info(f"Showing a saved investigation by `{who}`{via}{when}. "
            "Press **▶ Run live investigation** to watch an investigation happen.")

reports = [ss.reports[a["id"]] for a in alerts if a["id"] in ss.reports]
confirmed = [r for r in reports if r.get("verdict") == "true_positive"]
found = {t for r in confirmed for t in r.get("mitre", [])}
expected, hit = scenarios.technique_recall(truth, found)
avg_secs = (sum(r.get("seconds", 0) for r in reports) / len(reports)) if reports else None

k = st.columns(5)
k[0].metric("Events scanned", f"{len(df):,}", f"in {detect_secs:.2f}s", delta_color="off")
k[1].metric("Alerts raised", len(alerts))
k[2].metric("Confirmed attacks", len(confirmed) if reports else "—")
k[3].metric("Answer-key coverage", f"{len(hit)}/{len(expected)}" if reports and truth else "—",
            help="MITRE techniques in the scenario's answer key that the agent identified. "
                 "A sub-technique (T1021.002) counts for its parent (T1021). "
                 "Uploaded logs have no answer key.")
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
    todo = alerts
    if scenario == UPLOAD and PUBLIC and mode.startswith("Nemotron") and len(alerts) > MAX_UPLOAD_ALERTS:
        todo = sorted(alerts, key=lambda a: SEV_RANK.get(a["severity"], 9))[:MAX_UPLOAD_ALERTS]
        st.caption(f"Investigating the {MAX_UPLOAD_ALERTS} most severe of {len(alerts)} alerts "
                   "to keep the shared demo affordable. Run GHOST locally to investigate all.")
    for alert in todo:
        model = MockModel() if mode.startswith("Practice") else NIMModel()
        with st.status(f"🔎 Investigating {alert['id']}: {alert['summary']}",
                       expanded=True) as status:
            def show_step(t):
                st.write(f"**Step {t['step']}** · `{t['tool']}` → {t.get('summary', t['args'])}")
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
    # Only real Nemotron runs replace the saved results; a practice run never
    # overwrites them (on a shared server, visitors would erase each other's view)
    if mode.startswith("Nemotron") and not PUBLIC and REPORTS:
        REPORTS.parent.mkdir(exist_ok=True)
        REPORTS.write_text(json.dumps(prior, indent=2))


if run:
    if mode.startswith("Nemotron"):
        spend_live_run()
    ss.reports, ss.decisions, ss.showing_saved = {}, {}, False
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
                st.caption(" · ".join(f"{t} {technique_name(t)}"
                                      for t in r.get("mitre", [])))
        if i < len(confirmed) - 1:
            cols[i * 2 + 1].markdown("<h2 style='text-align:center;margin-top:12px'>→</h2>",
                                     unsafe_allow_html=True)


# ---------------------------------------------------------------- alert cards
st.subheader("Alerts")
if not reports and not run:
    st.info("Press **▶ Run live investigation** in the sidebar to watch the agent work.")

benign = {b["alert_id"]: b for b in scenarios.benign_results(truth, alerts, ss.reports)}

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
        link = str(r.get("related_to_prior") or "").strip()
        empty = ("null", "none", "n/a", "no ", "not ", "first alert")  # models write these as text
        if link and not link.lower().startswith(empty) and "is the first al" not in link.lower():
            st.caption(f"🔗 Linked to earlier alerts: {link}")

        left, right = st.columns(2)
        with left:
            st.markdown("**Evidence**")
            for e in r.get("evidence", []):
                st.markdown(f"- {e}")
            if r.get("mitre"):
                st.markdown("**MITRE ATT&CK**  \n" + "  ".join(
                    f"`{t}` {technique_name(t)}" for t in r["mitre"]))
            if r.get("candidate_mitre"):
                st.caption("🔍 Possible, suggested by the full MITRE ATT&CK search but not tied to "
                           "evidence, so not counted: " + ", ".join(
                               f"{t} {technique_name(t)}" for t in r["candidate_mitre"]))
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
                found = t.get("summary") or summarize_step(t["tool"], t["args"], t["result_preview"])
                st.markdown(f"**Step {t['step']}** · `{t['tool']}` → {found}")
                with st.popover("Raw tool output"):
                    st.code(t["result_preview"], language="json", wrap_lines=True)
