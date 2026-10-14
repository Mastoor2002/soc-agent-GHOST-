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
import html
import ipaddress
import json
import math
import os
import threading
import time
from datetime import date
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
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

VERDICT_LABEL = {"true_positive": ("tp", "Confirmed attack"),
                 "false_positive": ("fp", "False alarm"),
                 "needs_review": ("nr", "Needs human review")}
# Chart categories, in drawing order, with their colors
KINDS = {"Failed logins": "#e5484d", "Logins": "#3e63dd", "Programs & services": "#f5a623",
         "Network traffic": "#8b8d98", "Background (Windows)": "#3a3c44"}


# ---------------------------------------------------------------- look & feel
# Everything in this section only changes how the page LOOKS. Streamlit lets us
# inject CSS and HTML; the widgets (buttons, uploader, radio...) stay native.
def esc(text) -> str:
    """Model and log text is shown as plain text: escape HTML, and `$` so Streamlit
    never reads it as a math formula."""
    return html.escape(str(text)).replace("$", "&#36;").replace("\n", " ")


def ui(markup: str):
    """Draw a piece of HTML. Kept on one line so Markdown leaves it alone."""
    st.markdown(" ".join(markup.split("\n")), unsafe_allow_html=True)


def mitre_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + "/".join(str(tid).split(".")) + "/"


def mitre_chips(tids, cls="") -> str:
    """Technique tags that open the official MITRE ATT&CK page in a new tab."""
    return "".join(f'<a class="chip {cls}" href="{esc(mitre_url(t))}" target="_blank" '
                   f'title="Open {esc(t)} on attack.mitre.org"><code>{esc(t)}</code>'
                   f'{esc(technique_name(t))}</a>' for t in tids)


SEV_HEX = {"critical": "#ff4d5e", "high": "#ffa53a", "medium": "#4c9bff", "low": "#7d8b97"}
VERDICT_HEX = {"tp": "#ff4d5e", "fp": "#76b900", "nr": "#ffa53a"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
@property --n{syntax:'<integer>';inherits:false;initial-value:0}
@property --p{syntax:'<number>';inherits:false;initial-value:0}
:root{
  --bg:#060a0d; --glass:rgba(13,20,25,.74); --line:rgba(140,170,190,.13);
  --line-2:rgba(140,170,190,.22); --text:#e6edf1; --soft:#b9c6ce; --muted:#7f909b; --faint:#566670;
  --green:#76b900; --green-hi:#9be22a; --green-dim:rgba(118,185,0,.12); --green-line:rgba(118,185,0,.4);
  --glow:0 0 0 1px rgba(118,185,0,.25),0 0 24px rgba(118,185,0,.18);
  --crit:#ff4d5e; --high:#ffa53a; --med:#4c9bff; --low:#7d8b97;
  --display:'Chakra Petch','IBM Plex Sans',ui-sans-serif,sans-serif;
  --sans:'IBM Plex Sans',ui-sans-serif,system-ui,sans-serif;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
}
html,body,.stApp,[data-testid="stAppViewContainer"],.stMarkdown,.stMarkdown p,
[data-testid="stWidgetLabel"],button,input,textarea,select{font-family:var(--sans)!important}
code,pre,.stCode{font-family:var(--mono)!important}

/* the room: dark glass over a faint tactical grid with a green horizon glow */
.stApp{background:
  radial-gradient(1100px 520px at 72% -120px,rgba(118,185,0,.13),transparent 70%),
  radial-gradient(700px 400px at -5% 110%,rgba(76,155,255,.07),transparent 70%),
  linear-gradient(rgba(140,170,190,.045) 1px,transparent 1px) 0 0/44px 44px,
  linear-gradient(90deg,rgba(140,170,190,.045) 1px,transparent 1px) 0 0/44px 44px,
  var(--bg);background-attachment:fixed}
[data-testid="stAppViewContainer"],[data-testid="stMain"]{background:transparent}
[data-testid="stHeader"]{background:transparent}
[data-testid="stMainBlockContainer"],.block-container{padding-top:2rem;max-width:1340px}

/* sidebar: the control rack */
[data-testid="stSidebar"]{background:rgba(9,14,18,.92);border-right:1px solid var(--line);backdrop-filter:blur(10px)}
[data-testid="stSidebar"] h2{font-family:var(--display)!important;font-size:1rem;font-weight:600;letter-spacing:.06em;
  color:var(--text);padding-bottom:.7rem;border-bottom:1px solid var(--line);margin-bottom:.4rem}
[data-testid="stSidebar"] hr{border-color:var(--line)}
.stButton button,.stDownloadButton button{border-radius:6px;font-weight:500;border-color:var(--line-2);background:var(--glass)}
.stButton button[kind="primary"],[data-testid="stBaseButton-primary"]{
  background:linear-gradient(180deg,#86cc08,#69a600)!important;border:1px solid #8fd61a!important;color:#071000!important;
  font-weight:700;letter-spacing:.02em;box-shadow:0 0 0 1px rgba(118,185,0,.3),0 6px 22px rgba(118,185,0,.28);transition:box-shadow .2s,transform .2s}
.stButton button[kind="primary"]:hover,[data-testid="stBaseButton-primary"]:hover{
  box-shadow:0 0 0 1px rgba(155,226,42,.6),0 8px 32px rgba(118,185,0,.45);transform:translateY(-1px)}
.stButton button:disabled{background:var(--glass)!important;color:var(--faint)!important;border-color:var(--line)!important;box-shadow:none!important}
.stButton button:focus-visible,a:focus-visible{outline:2px solid var(--green-hi);outline-offset:2px}

/* headings */
h3,.h{font-family:var(--display)!important;font-size:1.05rem!important;font-weight:600!important;letter-spacing:.04em;
  color:var(--text);margin:1.8rem 0 .5rem!important;padding:0!important;display:flex;align-items:center;gap:.6rem}
h3::before,.h::before{content:"";width:14px;height:2px;background:var(--green);box-shadow:0 0 8px var(--green)}
.h .n{font-family:var(--mono);font-size:.75rem;font-weight:500;color:var(--green);border:1px solid var(--green-line);
  border-radius:4px;padding:0 .35rem}

/* top bar */
.topbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:.4rem}
.brand{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.logo{width:34px;height:34px;border-radius:8px;display:grid;place-items:center;border:1px solid var(--green-line);
  background:radial-gradient(circle at 50% 40%,rgba(118,185,0,.35),rgba(118,185,0,.05) 70%);box-shadow:var(--glow);font-size:18px}
.mark{font-family:var(--display);font-size:1.75rem;font-weight:700;letter-spacing:.32em;color:var(--text);line-height:1}
.sub{color:var(--muted);font-size:.84rem;max-width:42ch}
.state{display:inline-flex;align-items:center;gap:.55rem;font-family:var(--mono);font-size:.74rem;color:var(--soft);
  border:1px solid var(--line-2);border-radius:999px;padding:.32rem .8rem;background:var(--glass);backdrop-filter:blur(8px)}
.state .dot{width:8px;height:8px;border-radius:50%;background:var(--faint)}
.state.saved .dot,.state.live .dot{background:var(--green);box-shadow:0 0 10px var(--green)}
.state.live .dot{animation:blink 1.2s ease-in-out infinite}
.tag{color:var(--muted);font-size:.86rem;margin:.2rem 0 1rem}

/* HUD panel with corner brackets */
.hud{position:relative;background:var(--glass);border:1px solid var(--line);border-radius:10px;backdrop-filter:blur(12px)}
.hud::before,.hud::after{content:"";position:absolute;width:16px;height:16px;border:2px solid var(--green);pointer-events:none;opacity:.85;z-index:3}
.hud::before{top:-1px;left:-1px;border-right:none;border-bottom:none;border-top-left-radius:10px}
.hud::after{bottom:-1px;right:-1px;border-left:none;border-top:none;border-bottom-right-radius:10px}

/* hero: scenario brief + threat radar */
.hero{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:0;margin:.4rem 0 1rem;overflow:hidden}
.brief{padding:1.4rem 1.6rem 1.2rem}
.brief .kind{font-family:var(--mono);font-size:.72rem;color:var(--green);margin-bottom:.4rem}
.brief h1{font-family:var(--display)!important;font-size:1.7rem!important;font-weight:600!important;line-height:1.2;
  margin:0 0 .55rem!important;padding:0!important;letter-spacing:.01em}
.brief p{color:var(--soft);margin:0;max-width:72ch;line-height:1.6;font-size:.95rem}
.brief .src{margin-top:.8rem;font-size:.78rem;color:var(--muted)}
.brief .src a{color:var(--muted);text-decoration:underline;text-decoration-color:var(--line-2)}
.brief .src code{font-size:.72rem;color:var(--soft);background:rgba(118,185,0,.08);padding:.05rem .4rem;border-radius:4px;margin-left:.5rem}
.brief .run{margin-top:1rem;padding:.6rem .8rem;border-radius:6px;border:1px solid var(--line);background:rgba(6,10,13,.5);
  font-size:.82rem;color:var(--muted);line-height:1.5}
.brief .run b{color:var(--text);font-weight:500}
.brief .run code{font-size:.74rem;color:var(--green-hi);background:none;padding:0}
.radar-wrap{border-left:1px solid var(--line);padding:1.1rem 1rem 1rem;display:flex;flex-direction:column;align-items:center;
  background:linear-gradient(180deg,rgba(118,185,0,.05),transparent)}
.radar{position:relative;width:200px;height:200px;border-radius:50%;border:1px solid var(--green-line);
  background:repeating-radial-gradient(circle,transparent 0 24px,rgba(118,185,0,.16) 24px 25px),
  linear-gradient(transparent calc(50% - .5px),rgba(118,185,0,.18) calc(50% - .5px) calc(50% + .5px),transparent 0),
  linear-gradient(90deg,transparent calc(50% - .5px),rgba(118,185,0,.18) calc(50% - .5px) calc(50% + .5px),transparent 0),
  radial-gradient(circle,rgba(118,185,0,.08),rgba(6,10,13,.6) 70%);box-shadow:inset 0 0 30px rgba(118,185,0,.12),0 0 30px rgba(118,185,0,.08)}
.radar .sweep{position:absolute;inset:0;border-radius:50%;
  background:conic-gradient(from 0deg,rgba(118,185,0,.45),rgba(118,185,0,.08) 40deg,transparent 70deg);animation:spin 4.5s linear infinite}
.blip{position:absolute;width:12px;height:12px;margin:-6px 0 0 -6px;border-radius:50%;background:var(--c);
  box-shadow:0 0 12px var(--c);z-index:2;cursor:pointer;transition:transform .15s}
.blip::after{content:"";position:absolute;inset:-6px;border-radius:50%;border:1.5px solid var(--c);animation:ping 2.2s ease-out infinite;animation-delay:var(--d)}
.blip:hover{transform:scale(1.5)}
.blip.idle::after{display:none}
.threat{margin-top:.9rem;text-align:center}
.threat .lvl{font-family:var(--display);font-size:1.05rem;font-weight:700;letter-spacing:.08em;color:var(--tc)}
.threat .why{font-size:.75rem;color:var(--muted);margin-top:.15rem}
.legend{display:flex;gap:.7rem;flex-wrap:wrap;justify-content:center;margin-top:.55rem;font-size:.7rem;color:var(--muted)}
.legend i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:.3rem;background:var(--c);box-shadow:0 0 6px var(--c)}

/* KPI instruments */
.kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));margin:0 0 .4rem}
.kpi{padding:1rem 1.15rem .95rem;border-left:1px solid var(--line);min-width:0}
.kpi:first-child{border-left:none}
.kpi .k{font-size:.76rem;color:var(--muted);display:flex;align-items:center;gap:.35rem}
.kpi .k .q{width:15px;height:15px;border-radius:50%;border:1px solid var(--line-2);display:inline-grid;place-items:center;
  font-size:.62rem;cursor:help;color:var(--muted)}
.kpi .v{font-family:var(--display);font-size:2rem;font-weight:600;line-height:1.15;margin:.25rem 0 .35rem;color:var(--text);
  text-shadow:0 0 18px rgba(118,185,0,.18)}
.kpi .v.count{animation:count 1.4s cubic-bezier(.2,.7,.2,1) both;counter-reset:n var(--n)}
.kpi .v.count .num::after{content:counter(n)}
.kpi .v small{font-size:1rem;color:var(--muted);font-weight:500;margin-left:.1rem}
.kpi .d{font-size:.72rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi svg{display:block;width:100%;height:26px;margin-top:.3rem}
.segbar{display:flex;height:6px;border-radius:3px;overflow:hidden;background:rgba(140,170,190,.12);margin-top:.55rem;gap:2px}
.segbar i{display:block;height:100%;background:var(--c);box-shadow:0 0 8px var(--c);animation:grow 1.2s cubic-bezier(.2,.7,.2,1) both}

/* timeline */
.st-key-timeline{padding:1rem 1.1rem .5rem!important;background:var(--glass);border:1px solid var(--line)!important;border-radius:10px;backdrop-filter:blur(12px)}
.cap{color:var(--muted);font-size:.8rem;margin:0 0 .2rem;line-height:1.5}
.cap b{color:var(--soft);font-weight:500}

/* attack chain: stages on an animated green circuit */
.chain{display:grid;grid-auto-flow:column;grid-auto-columns:minmax(230px,1fr);gap:1rem;overflow-x:auto;padding:.3rem .1rem .6rem}
.stage{position:relative;display:block;text-decoration:none!important;color:inherit!important}
.stage .node{display:flex;align-items:center;margin-bottom:.75rem;height:30px}
.stage .num{flex:none;width:30px;height:30px;border-radius:7px;display:grid;place-items:center;background:var(--bg);
  border:1.5px solid var(--green);color:var(--green-hi);font-family:var(--display);font-weight:700;font-size:.9rem;box-shadow:var(--glow)}
.stage .wire{flex:1;height:2px;margin:0 -1rem 0 .6rem;
  background:repeating-linear-gradient(90deg,var(--green) 0 10px,transparent 10px 18px);background-size:36px 2px;
  opacity:.75;animation:flow 1.1s linear infinite}
.stage:last-child .wire{background:linear-gradient(90deg,var(--green-line),transparent);animation:none;margin-right:0}
.stage .card{padding:.85rem .95rem .6rem;border-radius:9px;border:1px solid var(--line);background:var(--glass);
  transition:border-color .2s,box-shadow .2s,transform .2s}
.stage:hover .card{border-color:var(--green-line);box-shadow:var(--glow);transform:translateY(-2px)}
.stage .t{font-weight:600;font-size:.9rem;line-height:1.35;margin-bottom:.55rem;color:var(--text)}
.stage .go{font-family:var(--mono);font-size:.7rem;color:var(--muted);margin-top:.15rem}
.stage:hover .go{color:var(--green-hi)}

/* chips (clickable MITRE tags) */
.chip{display:inline-flex;align-items:baseline;gap:.45rem;font-size:.76rem;color:var(--soft)!important;text-decoration:none!important;
  background:rgba(118,185,0,.06);border:1px solid rgba(118,185,0,.22);border-radius:5px;padding:.18rem .55rem;margin:0 .35rem .4rem 0;
  transition:background .15s,border-color .15s,box-shadow .15s}
a.chip:hover{background:rgba(118,185,0,.14);border-color:var(--green);box-shadow:0 0 12px rgba(118,185,0,.25)}
.chip code{font-family:var(--mono);font-size:.72rem;color:var(--green-hi);background:none;padding:0}
.chip.dim{background:rgba(140,170,190,.05);border-color:var(--line-2)}.chip.dim code{color:var(--muted)}
.chip.bad{background:rgba(255,165,58,.06);border-color:rgba(255,165,58,.3)}.chip.bad code{color:var(--high)}

/* alert filter */
.st-key-alert_filter button{font-size:.8rem!important}
.st-key-alert_filter button[kind="segmented_controlActive"],.st-key-alert_filter button[aria-checked="true"]{
  background:var(--green-dim)!important;color:var(--green-hi)!important;border-color:var(--green-line)!important}

/* alert cards: severity glows along the left edge */
[class*="st-key-sev-"]{border:1px solid var(--line)!important;border-radius:10px!important;background:var(--glass);
  backdrop-filter:blur(12px);padding:1.05rem 1.3rem 1rem 1.5rem!important;position:relative;overflow:hidden;
  transition:border-color .2s,box-shadow .2s}
[class*="st-key-sev-"]::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--sc);box-shadow:0 0 14px var(--sc)}
[class*="st-key-sev-"]:hover{border-color:color-mix(in srgb,var(--sc) 45%,transparent)!important;
  box-shadow:0 0 0 1px color-mix(in srgb,var(--sc) 20%,transparent),0 10px 40px -12px color-mix(in srgb,var(--sc) 35%,transparent)}
[class*="st-key-sev-critical"]{--sc:var(--crit)}[class*="st-key-sev-high"]{--sc:var(--high)}
[class*="st-key-sev-medium"]{--sc:var(--med)}[class*="st-key-sev-low"]{--sc:var(--low)}
.anchor{position:relative;top:-90px;height:0}
.ahead{display:flex;justify-content:space-between;align-items:flex-start;gap:1.2rem}
.aid{display:flex;align-items:center;gap:.65rem;flex-wrap:wrap;margin-bottom:.35rem}
.sev{font-family:var(--mono);font-size:.7rem;font-weight:500;padding:.12rem .5rem;border-radius:4px;color:var(--sc);
  background:color-mix(in srgb,var(--sc) 14%,transparent);border:1px solid color-mix(in srgb,var(--sc) 35%,transparent)}
.sev.critical{--sc:var(--crit)}.sev.high{--sc:var(--high)}.sev.medium{--sc:var(--med)}.sev.low{--sc:var(--low)}
.aid .id{font-family:var(--display);font-weight:600;font-size:.95rem;letter-spacing:.04em;color:var(--text)}
.aid .type{font-size:.8rem;color:var(--muted)}
.asum{color:var(--soft);font-size:.88rem;max-width:80ch;line-height:1.5}
.pending{font-family:var(--mono);font-size:.72rem;color:var(--faint);border:1px dashed var(--line-2);border-radius:999px;padding:.25rem .75rem;white-space:nowrap}
.verdict{display:flex;align-items:center;gap:.9rem;flex:none}
.vlabel{display:inline-flex;align-items:center;gap:.45rem;font-size:.82rem;font-weight:600;border-radius:999px;padding:.3rem .8rem;
  color:var(--vc);background:color-mix(in srgb,var(--vc) 12%,transparent);border:1px solid color-mix(in srgb,var(--vc) 35%,transparent);
  box-shadow:0 0 18px color-mix(in srgb,var(--vc) 18%,transparent)}
.vlabel::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.ring{width:56px;height:56px;border-radius:50%;flex:none;display:grid;place-items:center;position:relative;
  background:conic-gradient(var(--vc) calc(var(--p)*1%),rgba(140,170,190,.14) 0);animation:fill 1.2s cubic-bezier(.2,.7,.2,1) both}
.ring::before{content:"";position:absolute;inset:4px;border-radius:50%;background:#0b1217}
.ring span{position:relative;font-family:var(--display);font-weight:600;font-size:.85rem;color:var(--text);line-height:1;text-align:center}
.ring span small{display:block;font-family:var(--sans);font-size:.5rem;color:var(--muted);font-weight:400;margin-top:2px}
.finding{margin-top:.95rem;padding-top:.95rem;border-top:1px solid var(--line)}
.finding h4{font-size:1.05rem!important;font-weight:600!important;margin:0 0 .35rem!important;padding:0!important;line-height:1.35}
.finding .stxt{color:var(--soft);font-size:.91rem;line-height:1.6;max-width:86ch}
.linked{margin-top:.6rem;font-size:.78rem;color:var(--muted)}
.key{border-radius:7px;padding:.6rem .85rem;font-size:.84rem;margin:.9rem 0 0;line-height:1.5}
.key.ok{background:var(--green-dim);border:1px solid var(--green-line);color:#d9f0b5}
.key.bad{background:rgba(255,77,94,.08);border:1px solid rgba(255,77,94,.4);color:#ffc7cc}

/* tabs inside cards */
[class*="st-key-sev-"] [data-baseweb="tab-list"]{gap:.3rem;border-bottom:1px solid var(--line)}
[class*="st-key-sev-"] [data-baseweb="tab"]{padding:.45rem .75rem}
[class*="st-key-sev-"] [data-baseweb="tab"] p{font-size:.82rem;color:var(--muted)}
[class*="st-key-sev-"] [data-baseweb="tab"][aria-selected="true"] p{color:var(--green-hi)}
[data-baseweb="tab-highlight"]{background:var(--green)!important;box-shadow:0 0 10px var(--green)}
[data-baseweb="tab-border"]{display:none}
ul.ev{list-style:none;padding:0!important;margin:.2rem 0 0!important;display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:.45rem}
ul.ev li{margin:0!important;position:relative;padding:.55rem .75rem .55rem 2rem;font-size:.84rem;line-height:1.5;color:var(--soft);
  border:1px solid var(--line);border-radius:7px;background:rgba(6,10,13,.45)}
ul.ev li::before{content:attr(data-n);position:absolute;left:.6rem;top:.62rem;font-family:var(--mono);font-size:.66rem;color:var(--green)}
.lbl{font-size:.76rem;font-weight:500;color:var(--muted);margin:1rem 0 .5rem}
.lbl span{color:var(--faint);font-weight:400}
.note{font-size:.76rem;color:var(--muted);margin:.5rem 0 .4rem;line-height:1.5}
.act{font-size:.86rem;line-height:1.45;padding:.15rem 0}
.act code{font-size:.72rem;background:rgba(140,170,190,.08);color:var(--soft);padding:.05rem .4rem;border-radius:4px}
.act .pri{font-family:var(--mono);font-size:.66rem;color:var(--faint);margin-left:.45rem;border:1px solid var(--line-2);border-radius:3px;padding:0 .3rem}
.act .pri.immediate{color:var(--high);border-color:rgba(255,165,58,.35)}
.done{display:inline-block;font-family:var(--mono);font-size:.68rem;border-radius:4px;padding:.05rem .4rem;margin-right:.5rem}
.done.approved{color:var(--green-hi);background:var(--green-dim);border:1px solid var(--green-line)}
.done.rejected{color:var(--muted);background:rgba(140,170,190,.08);border:1px solid var(--line-2)}
.act.rejected .txt{color:var(--faint);text-decoration:line-through}
[class*="st-key-ok-"] button{border-color:var(--green-line)!important;color:var(--green-hi)!important;background:rgba(118,185,0,.06)!important}
[class*="st-key-ok-"] button:hover{background:var(--green-dim)!important;box-shadow:0 0 14px rgba(118,185,0,.3)}
[class*="st-key-no-"] button{color:var(--muted)!important;background:transparent!important}
[class*="st-key-no-"] button:hover{border-color:rgba(255,77,94,.55)!important;color:var(--crit)!important}
[class*="st-key-sev-"] .stButton button{padding:.15rem .5rem;min-height:2rem;font-size:.8rem;width:100%;white-space:nowrap}

/* trail */
.step{display:flex;gap:.75rem;align-items:baseline;font-size:.84rem;line-height:1.5;padding:.35rem 0;position:relative}
.step .sn{flex:none;width:24px;height:24px;margin-top:-3px;border-radius:50%;display:grid;place-items:center;font-family:var(--mono);
  font-size:.68rem;color:var(--green-hi);border:1px solid var(--green-line);background:#0b1217;align-self:flex-start}
.step .tool{flex:none;font-family:var(--mono);font-size:.74rem;color:var(--green-hi);background:var(--green-dim);padding:.04rem .45rem;border-radius:4px}
.step .res{color:var(--soft)}
.trailhead{display:flex;gap:1.4rem;font-family:var(--mono);font-size:.72rem;color:var(--muted);margin:.3rem 0 .5rem}
.trailhead b{color:var(--green-hi);font-weight:500}
[data-testid="stPopover"] button{white-space:nowrap;font-size:.72rem;padding:.05rem .5rem;min-height:1.6rem;color:var(--muted);border-color:var(--line)}

/* expanders / live run status */
[data-testid="stExpander"] details{border:1px solid var(--line)!important;border-radius:10px;background:var(--glass);backdrop-filter:blur(12px)}
[data-testid="stExpander"] summary p{font-size:.86rem}
[data-testid="stExpander"] details:has(summary [data-testid="stExpanderIconSpinner"]),
[data-testid="stExpander"] details:has(summary [data-testid="stSpinner"]){border-color:var(--green-line)!important;
  box-shadow:var(--glow);background-image:linear-gradient(90deg,transparent,rgba(118,185,0,.5),transparent);
  background-size:40% 2px;background-repeat:no-repeat;animation:scan 1.6s linear infinite}
[data-testid="stAlert"]{border-radius:8px}
.empty{border:1px dashed var(--green-line);border-radius:10px;padding:1.1rem 1.25rem;color:var(--muted);font-size:.9rem;margin:.5rem 0;
  background:rgba(118,185,0,.04)}
.empty b{color:var(--green-hi);font-weight:600}

@keyframes spin{to{transform:rotate(360deg)}}
@keyframes ping{0%{transform:scale(.6);opacity:.9}100%{transform:scale(2.2);opacity:0}}
@keyframes blink{50%{opacity:.35}}
@keyframes flow{to{background-position:36px 0}}
@keyframes count{from{--n:0}}
@keyframes grow{from{flex-grow:0}}
@keyframes fill{from{--p:0}}
@keyframes scan{from{background-position:-40% 0}to{background-position:140% 0}}

@media (max-width:900px){.hero{grid-template-columns:1fr}.radar-wrap{border-left:none;border-top:1px solid var(--line)}
  .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.kpi{border-left:none;border-top:1px solid var(--line)}
  .kpi:nth-child(-n+2){border-top:none}.ahead{flex-direction:column}.verdict{flex-direction:row-reverse;justify-content:flex-end}
  ul.ev{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


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


def topbar(state_cls: str, state_text: str):
    ui(f'''<div class="topbar"><div class="brand"><span class="logo">👻</span><span class="mark">GHOST</span>
       <span class="sub">Generative Hunting &amp; Operations Security Toolkit</span></div>
       <span class="state {state_cls}"><span class="dot"></span>{esc(state_text)}</span></div>''')


if scenario == UPLOAD and not uploaded:
    topbar("", "Waiting for a log file")
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


# ---------------------------------------------------------------- header
if run:
    topbar("live", "Investigating now")
elif ss.reports and ss.get("showing_saved"):
    topbar("saved", "Saved investigation loaded")
elif ss.reports:
    topbar("live", "Live investigation results")
else:
    topbar("", "Not investigated yet")
ui('<div class="tag">Fast detection finds the suspicious activity, then a Nemotron agent '
   "investigates each alert the way a human analyst would.</div>")
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

reports = [ss.reports[a["id"]] for a in alerts if a["id"] in ss.reports]
confirmed = [r for r in reports if r.get("verdict") == "true_positive"]
found = {t for r in confirmed for t in r.get("mitre", [])}
expected, hit = scenarios.technique_recall(truth, found)
avg_secs = (sum(r.get("seconds", 0) for r in reports) / len(reports)) if reports else None


# ---------------------------------------------------------------- activity data
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
pivot = (df.assign(bucket=df.timestamp.dt.floor(freq), kind=df.apply(kind, axis=1))
         .pivot_table(index="bucket", columns="kind", values="source", aggfunc="count",
                      fill_value=0))
cols = [c for c in KINDS if c in pivot.columns]


# ---------------------------------------------------------------- hero: brief + threat radar
def verdict_cls(a) -> str:
    """'tp' / 'fp' / 'nr' for an investigated alert, '' if not investigated yet."""
    r = ss.reports.get(a["id"])
    return VERDICT_LABEL.get(r.get("verdict"), ("nr", ""))[0] if r else ""


def verdict_text(a) -> str:
    r = ss.reports.get(a["id"])
    return VERDICT_LABEL.get(r.get("verdict"), ("", "Needs human review"))[1] if r \
        else "Not investigated yet"


brief_src, brief_run = "", ""
if ctx.get("source_url"):
    url = esc(ctx["source_url"])
    brief_src = (f'<div class="src">Data source: <a href="{url}" target="_blank">{url}</a>'
                 + (f'<code>dataset {esc(ctx["otrf_id"])}</code>' if ctx.get("otrf_id") else "")
                 + "</div>")
if ss.get("showing_saved") and ss.reports:
    first = next(iter(ss.reports.values()))
    who = first.get("model") or "NVIDIA Nemotron"
    via = f" via {esc(first['provider'])}" if first.get("provider") else ""
    when = f", run on {esc(first['run_date'])}" if first.get("run_date") else ""
    brief_run = (f'<div class="run">Showing a saved investigation by <code>{esc(who)}</code>{via}'
                 f'{when}. Press <b>▶ Run live investigation</b> to watch an investigation '
                 "happen.</div>")

# Each alert is a blip: the closer to the centre, the more severe. Colour = verdict.
RADIUS = {"critical": 20, "high": 33, "medium": 41, "low": 45}
blips = ""
for i, a in enumerate(alerts):
    ang = math.radians(i * 360 / max(len(alerts), 1) - 60)
    rad = RADIUS.get(a["severity"], 45) - 4 * (i % 2)
    vc = verdict_cls(a)
    tip = f'{a["id"]} ({a["severity"]}): {verdict_text(a)}. {a["summary"]}'
    blips += (f'<a class="blip {"" if vc else "idle"}" href="#card-{esc(a["id"])}" title="{esc(tip)}" '
              f'style="left:{50 + rad * math.cos(ang):.1f}%;top:{50 + rad * math.sin(ang):.1f}%;'
              f'--c:{VERDICT_HEX.get(vc, "#8b98a3")};--d:{i * 0.35:.2f}s"></a>')
if confirmed:
    worst = min((a["severity"] for a in alerts if verdict_cls(a) == "tp"),
                key=lambda s: SEV_RANK.get(s, 9))
    level, lcolor = f"{worst.capitalize()} threat", SEV_HEX.get(worst, "#ff4d5e")
    why = (f"{len(confirmed)} confirmed attack{'s' if len(confirmed) != 1 else ''} "
           f"in {len(alerts)} alerts")
elif reports:
    level, lcolor, why = "No confirmed attack", "#76b900", f"{len(reports)} alerts investigated"
else:
    level, lcolor, why = "Awaiting investigation", "#7f909b", f"{len(alerts)} alerts raised"
ui(f'''<div class="hud hero"><div class="brief">{"" if scenario == UPLOAD
       else '<div class="kind">Scenario</div>'}<h1>{esc(ctx.get('title', scenario))}</h1>
       <p>{esc(ctx.get('description', ''))}</p>{brief_src}{brief_run}</div>
       <div class="radar-wrap"><div class="radar"><div class="sweep"></div>{blips}</div>
       <div class="threat" style="--tc:{lcolor}"><div class="lvl">{esc(level)}</div>
       <div class="why">{esc(why)}</div></div>
       <div class="legend"><span style="--c:#ff4d5e"><i></i>Attack</span>
       <span style="--c:#76b900"><i></i>False alarm</span><span style="--c:#ffa53a"><i></i>Review</span>
       <span style="--c:#8b98a3"><i></i>Pending</span></div></div></div>''')


# ---------------------------------------------------------------- KPIs
def num(value: int) -> str:
    """Small numbers count up from zero when the page draws; big ones show with commas."""
    if 0 < value < 1000:
        return f'<div class="v count" style="--n:{value}"><span class="num"></span>'
    return f'<div class="v">{value:,}'


totals = pivot[cols].sum(axis=1).tolist() if cols else []
spark = ""
if len(totals) > 1:
    top = max(totals) or 1
    pts = " ".join(f"{i * 200 / (len(totals) - 1):.1f},{24 - v / top * 22:.1f}"
                   for i, v in enumerate(totals))
    spark = (f'<svg viewBox="0 0 200 26" preserveAspectRatio="none"><polygon points="0,26 {pts} '
             '200,26" fill="rgba(118,185,0,.12)"/><polyline points="' + pts + '" fill="none" '
             'stroke="#76b900" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>')
sev_counts = {s: sum(a["severity"] == s for a in alerts) for s in SEV_HEX}
sev_bar = "".join(f'<i style="flex-grow:{n};--c:{SEV_HEX[s]}" title="{n} {s}"></i>'
                  for s, n in sev_counts.items() if n)
v_counts = {c: sum(verdict_cls(a) == c for a in alerts) for c in ("tp", "nr", "fp", "")}
v_bar = "".join(f'<i style="flex-grow:{n};--c:{VERDICT_HEX.get(c, "#3a4650")}"></i>'
                for c, n in v_counts.items() if n)
cov_help = ("MITRE techniques in the scenario's answer key that the agent identified. "
            "A sub-technique (T1021.002) counts for its parent (T1021). "
            "Uploaded logs have no answer key.")
cov = ""
if reports and truth:
    cov = (f'{num(len(hit))}<small>/{len(expected)}</small></div>'
           f'<div class="segbar"><i style="flex-grow:{len(hit)};--c:#76b900"></i>'
           f'<i style="flex-grow:{len(expected) - len(hit)};--c:#3a4650;box-shadow:none"></i></div>')
tiles = [
    ("Events scanned", f'{num(len(df))}</div><div class="d">in {detect_secs:.2f}s</div>{spark}'),
    ("Alerts raised", f'{num(len(alerts))}</div><div class="segbar">{sev_bar}</div>'),
    ("Confirmed attacks", (f'{num(len(confirmed))}</div><div class="segbar">{v_bar}</div>'
                           if reports else '<div class="v">—</div>')),
    ("Answer-key coverage", cov or '<div class="v">—</div>'),
    ("Avg triage time", (f'{num(round(avg_secs))}<small>s</small></div>'
                         '<div class="d">vs ~15 min manual (estimate)</div>'
                         if avg_secs else '<div class="v">—</div>')),
]
ui('<div class="hud kpis">' + "".join(
    f'<div class="kpi"><div class="k">{label}'
    + (f'<span class="q" title="{esc(cov_help)}">?</span>' if label.startswith("Answer") else "")
    + f"</div>{body}</div>" for label, body in tiles) + "</div>")


# ---------------------------------------------------------------- live attack map
# A replay of this scenario's logs as a network: the real hosts and IP addresses are
# the nodes, logged connections are the links, and the GHOST probe roams from node
# to node along each alert's path, locking on to what the agent confirmed.
SKIP_IP = ("0:0:0:0:0:0:0:1", "::1", "127.0.0.1")


def _ip_zone(ip: str) -> str:
    """'internal' for company addresses (from the scenario's known ranges, or any
    private range), 'external' otherwise."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "internal"
    for net in ctx.get("known_subnets", []):
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return "internal"
        except ValueError:
            pass
    return "internal" if addr.is_private else "external"


def _keep(v) -> bool:
    s = str(v)
    return bool(v) and s not in ("nan", "None", "") and s not in SKIP_IP \
        and not s.startswith("fe80") and not s.endswith(".255")


def map_data(focus: str | None = None) -> dict:
    nodes, edges = {}, {}

    def node(name, kind):
        name = str(name)
        if name not in nodes:
            nodes[name] = {"id": name, "kind": kind, "alerts": [], "status": "clean", "n": 0}
        return nodes[name]

    def edge(a, b, attack=False, n=1):
        if a == b:
            return
        e = edges.setdefault((a, b), {"s": a, "t": b, "n": 0, "attack": False})
        e["n"] += n
        e["attack"] = e["attack"] or attack

    # Alerts first, so their machines are always on the map.
    paths = []
    for a in alerts:
        path = []
        if _keep(a.get("src_ip")):
            path.append(node(a["src_ip"], _ip_zone(str(a["src_ip"])))["id"])
        if _keep(a.get("host")):
            path.append(node(a["host"], "host")["id"])
        for h in a.get("hosts") or []:
            path.append(node(h, "host")["id"])
        if _keep(a.get("dst_ip")):
            path.append(node(a["dst_ip"], _ip_zone(str(a["dst_ip"])))["id"])
        vc = verdict_cls(a)
        status = {"tp": "attack", "fp": "cleared", "nr": "review"}.get(vc, "pending")
        rank = {"attack": 4, "review": 3, "pending": 2, "cleared": 1, "clean": 0}
        for p in path:
            nodes[p]["alerts"].append(a["id"])
            if rank[status] > rank[nodes[p]["status"]]:
                nodes[p]["status"] = status
        for x, y in zip(path, path[1:]):
            edge(x, y, attack=True)
        paths.append({"id": a["id"], "path": path, "status": status, "sev": a["severity"],
                      "title": (ss.reports.get(a["id"]) or {}).get("title") or a["summary"]})

    # Then the busiest real connections in the logs, as background traffic.
    cols_ = [c for c in ("host", "src_ip", "dst_ip") if c in df.columns]
    pairs = []
    if "src_ip" in cols_ and "host" in cols_:
        pairs.append(df[["src_ip", "host"]].rename(columns={"src_ip": "a", "host": "b"}))
    if "host" in cols_ and "dst_ip" in cols_:
        pairs.append(df[["host", "dst_ip"]].rename(columns={"host": "a", "dst_ip": "b"}))
    if "src_ip" in cols_ and "dst_ip" in cols_:
        pairs.append(df[["src_ip", "dst_ip"]].rename(columns={"src_ip": "a", "dst_ip": "b"}))
    if pairs:
        allp = pd.concat(pairs).dropna()
        allp = allp[allp.a.map(_keep) & allp.b.map(_keep)]
        counts = allp.groupby(["a", "b"]).size().sort_values(ascending=False)
        for (x, y), n in counts.items():
            if len(nodes) >= 26 and (str(x) not in nodes or str(y) not in nodes):
                continue
            hosts = set(df.host.dropna().astype(str)) if "host" in df.columns else set()
            for v in (x, y):
                node(v, "host" if str(v) in hosts else _ip_zone(str(v)))
            edge(str(x), str(y), n=int(n))
            if len(edges) >= 40:
                break
    if "host" in df.columns:  # quiet machines that only log locally
        for h, n in df.host.value_counts().head(12).items():
            node(h, "host")["n"] += int(n)

    # A rolling feed of real log lines, weighted towards the moments alerts fired.
    feed = []
    if len(df):
        ts = df.timestamp
        picks = set(df.sample(min(len(df), 36), random_state=7).index)
        for a in alerts:
            t = pd.to_datetime(a.get("time"), errors="coerce")
            if pd.notna(t):
                picks |= set((ts - t).abs().nsmallest(4).index)
        for i in sorted(picks, key=lambda i: ts[i]):
            r = df.loc[i]
            bits = [str(r.get(c)) for c in ("event", "user") if _keep(r.get(c))]
            if _keep(r.get("process")):  # just the program name, not its full path
                bits.append(str(r.get("process")).replace("\\", "/").split("/")[-1])
            src, dst = r.get("src_ip"), r.get("dst_ip")
            if _keep(src) or _keep(dst):
                bits.append(f"{src if _keep(src) else '?'} > {dst if _keep(dst) else '?'}")
            hot = any(abs((ts[i] - pd.to_datetime(a.get("time"), errors="coerce"))
                          .total_seconds()) < 2 for a in alerts if a.get("time"))
            feed.append({"t": ts[i].strftime("%H:%M:%S"), "h": str(r.get("host") or ""),
                         "m": " ".join(bits)[:90], "hot": bool(hot)})
    return {"nodes": list(nodes.values()), "edges": list(edges.values()), "paths": paths,
            "feed": feed[:70], "focus": focus,
            "title": ctx.get("title", scenario)}


MAP_HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--g:#76b900;--gh:#9be22a;--r:#ff4d5e;--a:#ffa53a;--b:#4c9bff;--t:#e6edf1;--m:#7f909b;--line:rgba(140,170,190,.14)}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:transparent;color:var(--t);
 font-family:'JetBrains Mono',ui-monospace,monospace;overflow:hidden}
.wrap{position:absolute;inset:0;display:grid;grid-template-columns:minmax(0,1fr) 270px;border:1px solid var(--line);
 border-radius:10px;overflow:hidden;background:radial-gradient(900px 400px at 40% 0%,rgba(118,185,0,.10),transparent 70%),rgba(8,13,17,.92)}
canvas{width:100%;height:100%;display:block;cursor:grab}
.stage{position:relative;min-width:0}
.hud{position:absolute;left:10px;top:10px;pointer-events:none;background:rgba(8,13,17,.78);border:1px solid rgba(140,170,190,.12);border-radius:7px;padding:8px 11px;backdrop-filter:blur(4px);max-width:calc(100% - 200px)}
.hud .k{font-size:10px;color:var(--m);letter-spacing:.08em}
.hud .live{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:var(--gh)}
.hud .live i{width:7px;height:7px;border-radius:50%;background:var(--g);box-shadow:0 0 8px var(--g);animation:bl 1.1s infinite}
.hud .st{margin-top:6px;font-family:'Chakra Petch',sans-serif;font-weight:700;font-size:15px;letter-spacing:.06em}
.hud .sub{font-size:11px;color:var(--m);margin-top:2px;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.legend{position:absolute;left:14px;bottom:10px;display:flex;gap:12px;flex-wrap:wrap;font-size:10px;color:var(--m);pointer-events:none}
.legend span{display:inline-flex;align-items:center;gap:5px}.legend i{width:8px;height:8px;border-radius:50%;display:inline-block}
.ctrl{position:absolute;right:10px;top:10px;display:flex;gap:6px}
.ctrl button{font:inherit;font-size:10px;color:var(--t);background:rgba(13,20,25,.85);border:1px solid var(--line);
 border-radius:5px;padding:4px 8px;cursor:pointer}.ctrl button:hover{border-color:var(--g);color:var(--gh)}
.ctrl button.on{border-color:rgba(118,185,0,.5);color:var(--gh)}
.tip{position:absolute;pointer-events:none;background:rgba(6,10,13,.95);border:1px solid rgba(118,185,0,.4);border-radius:6px;
 padding:6px 8px;font-size:11px;line-height:1.45;max-width:260px;display:none;z-index:5}
.feed{border-left:1px solid var(--line);display:flex;flex-direction:column;min-height:0;background:rgba(6,10,13,.55)}
.feed .hd{padding:10px 12px 8px;font-size:10px;color:var(--m);letter-spacing:.08em;border-bottom:1px solid var(--line);display:flex;justify-content:space-between}
.feed .hd b{color:var(--gh);font-weight:500}
.rows{flex:1;overflow:hidden;position:relative;mask-image:linear-gradient(transparent,#000 12%,#000 88%,transparent)}
.row{padding:5px 12px;font-size:10.5px;line-height:1.4;color:#a9b6be;border-bottom:1px solid rgba(140,170,190,.06);animation:in .4s ease-out}
.row .tm{color:var(--m)}.row .hs{color:var(--b)}
.row.hot{color:#ffc7cc;background:linear-gradient(90deg,rgba(255,77,94,.14),transparent)}.row.hot .hs{color:var(--r)}
@keyframes bl{50%{opacity:.3}}@keyframes in{from{opacity:0;transform:translateY(-6px)}}
@media (max-width:640px){.wrap{grid-template-columns:1fr}.feed{display:none}}
</style></head><body>
<div class="wrap"><div class="stage"><canvas id="c"></canvas>
<div class="hud"><div class="live"><i></i><span id="mode">LIVE REPLAY</span></div>
<div class="st" id="st">SWEEPING NETWORK</div><div class="sub" id="sub"></div></div>
<div class="ctrl"><button id="roam" class="on" title="Let the camera follow the GHOST probe">Auto-roam</button>
<button id="reset" title="Show the whole network">Overview</button></div>
<div class="legend"><span><i style="background:#ff4d5e"></i>Attack confirmed</span><span><i style="background:#ffa53a"></i>Under investigation</span>
<span><i style="background:#76b900"></i>Cleared</span><span><i style="background:#4c9bff"></i>Company machine</span>
<span><i style="background:#c08cff"></i>Outside address</span></div>
<div class="tip" id="tip"></div></div>
<div class="feed"><div class="hd"><span>LOG STREAM</span><b id="cnt"></b></div><div class="rows" id="rows"></div></div></div>
<script>
const D = __DATA__;
const cv = document.getElementById('c'), cx = cv.getContext('2d');
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
let W = 0, H = 0, dpr = Math.min(devicePixelRatio || 1, 2);
function size(){ const r = cv.getBoundingClientRect(); W = r.width; H = r.height; cv.width = W*dpr; cv.height = H*dpr; }
size(); addEventListener('resize', () => { size(); Object.assign(ov, fit()); });

const COL = {attack:'#ff4d5e', review:'#ffa53a', pending:'#ffa53a', cleared:'#76b900', clean:null};
const byId = {};
D.nodes.forEach((n,i) => {
  const ext = n.kind === 'external';
  const a = (i * 2.399) % (Math.PI*2);
  n.x = (ext ? -260 : 120) + Math.cos(a) * (ext ? 60 : 150) + (Math.random()-.5)*40;
  n.y = Math.sin(a) * (ext ? 150 : 120);
  n.vx = 0; n.vy = 0; n.r = n.kind === 'host' ? 9 : 6; n.ph = Math.random()*6.28;
  byId[n.id] = n;
});
D.edges.forEach(e => { e.a = byId[e.s]; e.b = byId[e.t]; });
const E = D.edges.filter(e => e.a && e.b);

// gentle force layout: links pull, nodes push, outside addresses drift left
function physics(){
  for (const a of D.nodes){ for (const b of D.nodes){ if (a === b) continue;
    let dx = a.x-b.x, dy = a.y-b.y, d2 = dx*dx+dy*dy+.01; if (d2 > 160000) continue;
    const f = 1500/d2; a.vx += dx*f*.05; a.vy += dy*f*.05; } }
  for (const e of E){ const dx = e.b.x-e.a.x, dy = e.b.y-e.a.y, d = Math.hypot(dx,dy)+.01;
    const f = (d-(e.attack?130:105))*.004; e.a.vx += dx/d*f*d*.05; e.a.vy += dy/d*f*d*.05; e.b.vx -= dx/d*f*d*.05; e.b.vy -= dy/d*f*d*.05; }
  for (const n of D.nodes){ n.vx += ((n.kind==='external'?-230:110)-n.x)*.0016; n.vy += (0-n.y)*.0016;
    n.vx *= .82; n.vy *= .82; n.x += n.vx; n.y += n.vy; }
}
for (let i = 0; i < 260; i++) physics();

// camera that roams after the probe
const cam = {x:0, y:0, z:1, tx:0, ty:0, tz:1};
let roam = true, pinned = null, drag = null;
function fit(){ let xs = D.nodes.map(n=>n.x), ys = D.nodes.map(n=>n.y);
  if (!xs.length) return {x:0,y:0,z:1};
  const minx = Math.min(...xs), maxx = Math.max(...xs), miny = Math.min(...ys), maxy = Math.max(...ys);
  return {x:(minx+maxx)/2, y:(miny+maxy)/2 - 22, z:Math.max(.35, Math.min(1.6, Math.min((W-60)/(maxx-minx+150), (H-120)/(maxy-miny+110))))}; }
const ov = fit(); Object.assign(cam, {x:ov.x, y:ov.y, z:ov.z});
const S = (x,y) => [(x-cam.x)*cam.z + W/2, (y-cam.y)*cam.z + H/2];

// the probe's tour: overview, then each alert path in order
const tour = [];
const focus = D.focus;
D.paths.filter(p => p.path.length && (!focus || p.id === focus)).forEach(p => {
  p.path.forEach((id,i) => tour.push({node:id, path:p, last:i === p.path.length-1})); });
const probe = {x:ov.x-200, y:ov.y, step:-1, t:0, hold:0, trail:[]};
let state = {st:'SWEEPING NETWORK', sub:'Scanning ' + D.nodes.length + ' machines and addresses from the logs', col:'#9be22a'};
function nextStop(){
  probe.step++;
  if (probe.step >= tour.length){ probe.step = -1; probe.hold = 150;
    state = {st:'SWEEPING NETWORK', sub:'Scanning ' + D.nodes.length + ' machines and addresses from the logs', col:'#9be22a'}; return; }
  const s = tour[probe.step], n = byId[s.node]; probe.target = n; probe.hold = s.last ? 110 : 55;
  const p = s.path, live = focus && p.id === focus;
  const word = live ? 'INVESTIGATING' : {attack:'THREAT LOCKED', cleared:'CLEARED: FALSE ALARM', review:'NEEDS HUMAN REVIEW', pending:'TRACING'}[p.status];
  state = {st: word + ' · ' + p.id, sub: n.id + ' · ' + p.title,
           col: live ? '#ffa53a' : (COL[p.status] || '#9be22a')};
}
if (!tour.length) probe.hold = 1e9;

// particles riding the links
const parts = [];
E.forEach(e => { const k = e.attack ? 3 : Math.min(3, 1 + Math.log10(e.n+1));
  for (let i = 0; i < k; i++) parts.push({e, u:Math.random(), v:(e.attack?.006:.003)*(.6+Math.random()*.8)}); });

const st = document.getElementById('st'), sub = document.getElementById('sub');
let lastSt = '';
function hud(){ const key = state.st + state.sub; if (key === lastSt) return; lastSt = key;
  st.textContent = state.st; st.style.color = state.col; sub.textContent = state.sub;
  document.getElementById('mode').textContent = focus ? 'LIVE INVESTIGATION' : 'LIVE REPLAY'; }

function nodeColor(n){ if (COL[n.status]) return COL[n.status]; return n.kind === 'external' ? '#c08cff' : '#4c9bff'; }
let tick = 0;
function frame(){
  tick++;
  if (!reduce) physics();
  if (tick % 30 === 0 || W < 50){ size(); Object.assign(ov, fit()); }
  // probe movement
  if (probe.hold > 0) probe.hold--; else if (tour.length) nextStop();
  const tgt = probe.step >= 0 ? probe.target : {x: ov.x + Math.cos(tick/90)*160, y: ov.y + Math.sin(tick/70)*90};
  probe.x += (tgt.x - probe.x) * .06; probe.y += (tgt.y - probe.y) * .06;
  probe.trail.push([probe.x, probe.y]); if (probe.trail.length > 26) probe.trail.shift();
  // camera
  if (pinned){ cam.tx = pinned.x; cam.ty = pinned.y; cam.tz = Math.max(ov.z, 1.5); }
  else if (roam && probe.step >= 0){ cam.tx = probe.x; cam.ty = probe.y; cam.tz = Math.max(ov.z*1.35, 1.25); }
  else if (!drag){ cam.tx = ov.x + Math.sin(tick/300)*20; cam.ty = ov.y + Math.cos(tick/260)*12; cam.tz = ov.z; }
  if (!drag){ cam.x += (cam.tx-cam.x)*.035; cam.y += (cam.ty-cam.y)*.035; cam.z += (cam.tz-cam.z)*.035; }

  cx.setTransform(dpr,0,0,dpr,0,0); cx.clearRect(0,0,W,H);
  // grid that moves with the camera
  cx.strokeStyle = 'rgba(140,170,190,.06)'; cx.lineWidth = 1; const g = 46*cam.z;
  const ox = ((-cam.x*cam.z + W/2) % g + g) % g, oy = ((-cam.y*cam.z + H/2) % g + g) % g;
  cx.beginPath(); for (let x = ox; x < W; x += g){ cx.moveTo(x,0); cx.lineTo(x,H); }
  for (let y = oy; y < H; y += g){ cx.moveTo(0,y); cx.lineTo(W,y); } cx.stroke();
  // links
  for (const e of E){ const [x1,y1] = S(e.a.x,e.a.y), [x2,y2] = S(e.b.x,e.b.y);
    const hot = e.attack && (e.a.status === 'attack' || e.b.status === 'attack');
    cx.strokeStyle = e.attack ? (hot ? 'rgba(255,77,94,.55)' : 'rgba(255,165,58,.4)') : 'rgba(140,170,190,.16)';
    cx.lineWidth = e.attack ? 1.6 : 1; cx.setLineDash(e.attack ? [6,5] : []); cx.lineDashOffset = -tick*.6;
    cx.beginPath(); cx.moveTo(x1,y1); cx.lineTo(x2,y2); cx.stroke(); }
  cx.setLineDash([]);
  // packets
  for (const p of parts){ if (!reduce) { p.u += p.v; if (p.u > 1) p.u -= 1; }
    const e = p.e, x = e.a.x + (e.b.x-e.a.x)*p.u, y = e.a.y + (e.b.y-e.a.y)*p.u, [sx,sy] = S(x,y);
    const c = e.attack ? ((e.a.status==='attack'||e.b.status==='attack') ? '#ff4d5e' : '#ffa53a') : '#6fa8ff';
    cx.fillStyle = c; cx.shadowColor = c; cx.shadowBlur = 8; cx.beginPath(); cx.arc(sx,sy,e.attack?2.4:1.6,0,7); cx.fill(); }
  cx.shadowBlur = 0;
  // nodes
  for (const n of D.nodes){ const [x,y] = S(n.x,n.y), c = nodeColor(n), r = n.r*Math.min(cam.z,1.6);
    if (n.status === 'attack' || n.status === 'review' || n.status === 'pending'){
      const k = (tick/60 + n.ph) % 1; cx.strokeStyle = c; cx.globalAlpha = 1-k; cx.lineWidth = 1.5;
      cx.beginPath(); cx.arc(x,y,r+4+k*18,0,7); cx.stroke(); cx.globalAlpha = 1; }
    cx.fillStyle = '#0b1217'; cx.strokeStyle = c; cx.lineWidth = 2; cx.shadowColor = c; cx.shadowBlur = n.status==='clean'?6:16;
    cx.beginPath(); if (n.kind === 'host'){ cx.rect(x-r,y-r,r*2,r*2); } else { cx.arc(x,y,r,0,7); }
    cx.fill(); cx.stroke(); cx.shadowBlur = 0;
    cx.fillStyle = c; cx.beginPath(); cx.arc(x,y,r*.38,0,7); cx.fill();
    cx.font = (n.status==='clean'?'400 ':'500 ') + '10px JetBrains Mono, monospace';
    cx.fillStyle = n.status === 'clean' ? 'rgba(185,198,206,.7)' : '#e6edf1';
    cx.fillText(n.id, x + r + 6, y + 3.5); }
  // probe
  const [px,py] = S(probe.x, probe.y);
  cx.strokeStyle = 'rgba(155,226,42,.25)'; cx.lineWidth = 2; cx.beginPath();
  probe.trail.forEach(([x,y],i) => { const [sx,sy] = S(x,y); i ? cx.lineTo(sx,sy) : cx.moveTo(sx,sy); }); cx.stroke();
  const pc = state.col;
  cx.save(); cx.translate(px,py); cx.rotate(tick/22);
  cx.strokeStyle = pc; cx.lineWidth = 1.6; cx.shadowColor = pc; cx.shadowBlur = 12;
  for (let q = 0; q < 4; q++){ cx.beginPath(); cx.arc(0,0,20,q*Math.PI/2+.25,q*Math.PI/2+1.25); cx.stroke(); }
  cx.restore();
  const cone = cx.createRadialGradient(px,py,0,px,py,60); cone.addColorStop(0, pc+'55'); cone.addColorStop(1, pc+'00');
  cx.fillStyle = cone; cx.beginPath(); cx.moveTo(px,py); cx.arc(px,py,60,tick/18,tick/18+.9); cx.closePath(); cx.fill();
  cx.strokeStyle = pc; cx.lineWidth = 1; cx.beginPath(); cx.moveTo(px-28,py); cx.lineTo(px-12,py); cx.moveTo(px+12,py); cx.lineTo(px+28,py);
  cx.moveTo(px,py-28); cx.lineTo(px,py-12); cx.moveTo(px,py+12); cx.lineTo(px,py+28); cx.stroke();
  cx.font = '700 10px Chakra Petch, sans-serif'; cx.fillStyle = pc; cx.fillText('GHOST', px+16, py-18);
  hud();
  requestAnimationFrame(frame);
}
requestAnimationFrame(frame);

// interaction: hover for details, click a node to lock the camera on it, drag to pan, wheel to zoom
const tip = document.getElementById('tip');
function hit(mx,my){ for (const n of D.nodes){ const [x,y] = S(n.x,n.y); if (Math.hypot(mx-x,my-y) < n.r*cam.z+6) return n; } return null; }
cv.addEventListener('mousemove', ev => { const r = cv.getBoundingClientRect(), mx = ev.clientX-r.left, my = ev.clientY-r.top;
  if (drag){ cam.x = drag.cx - (mx-drag.mx)/cam.z; cam.y = drag.cy - (my-drag.my)/cam.z; cam.tx = cam.x; cam.ty = cam.y; return; }
  const n = hit(mx,my); cv.style.cursor = n ? 'pointer' : 'grab';
  if (n){ const kind = n.kind === 'host' ? 'Company machine' : n.kind === 'external' ? 'Outside address' : 'Company address';
    const s = {attack:'Attack confirmed', review:'Needs human review', pending:'Not investigated yet', cleared:'False alarm, cleared', clean:'No alerts'}[n.status];
    tip.innerHTML = '<b>' + n.id.replace(/</g,'&lt;') + '</b><br>' + kind + '<br>' + s + (n.alerts.length ? '<br>' + n.alerts.join(', ') : '');
    tip.style.display = 'block'; tip.style.left = Math.min(mx+14, W-270) + 'px'; tip.style.top = (my+14) + 'px'; }
  else tip.style.display = 'none'; });
cv.addEventListener('mouseleave', () => { tip.style.display = 'none'; drag = null; });
cv.addEventListener('mousedown', ev => { const r = cv.getBoundingClientRect(), mx = ev.clientX-r.left, my = ev.clientY-r.top;
  const n = hit(mx,my); if (n){ pinned = pinned === n ? null : n; return; }
  drag = {mx, my, cx:cam.x, cy:cam.y}; roam = false; btn.classList.remove('on'); cv.style.cursor = 'grabbing'; });
addEventListener('mouseup', () => { drag = null; });
cv.addEventListener('wheel', ev => { ev.preventDefault(); roam = false; btn.classList.remove('on');
  cam.tz = cam.z = Math.max(.4, Math.min(3, cam.z * (ev.deltaY < 0 ? 1.12 : .89))); }, {passive:false});
const btn = document.getElementById('roam');
btn.onclick = () => { roam = !roam; pinned = null; btn.classList.toggle('on', roam); };
document.getElementById('reset').onclick = () => { roam = false; pinned = null; btn.classList.remove('on');
  const f = fit(); Object.assign(ov, f); cam.tx = f.x; cam.ty = f.y; cam.tz = f.z; };

// log stream
const rows = document.getElementById('rows'), cnt = document.getElementById('cnt');
let fi = 0, seen = 0;
function push(){ if (!D.feed.length) return; const f = D.feed[fi++ % D.feed.length]; seen++;
  const d = document.createElement('div'); d.className = 'row' + (f.hot ? ' hot' : '');
  const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  d.innerHTML = '<span class="tm">' + esc(f.t) + '</span> <span class="hs">' + esc(f.h) + '</span> ' + esc(f.m);
  rows.prepend(d); while (rows.children.length > 40) rows.lastChild.remove();
  cnt.textContent = seen + ' events'; }
for (let i = 0; i < 12; i++) push();
if (!reduce) setInterval(push, 650);
</script></body></html>"""


def attack_map(focus: str | None = None, height: int = 430):
    data = json.dumps(map_data(focus), default=str).replace("</", "<\\/")
    components.html(MAP_HTML.replace("__DATA__", data), height=height)

if not run:  # during a live run the map is drawn in the live section instead
    ui('<div class="h">Live attack map</div>')
    ui('<div class="cap">A replay built from this scenario\'s logs: the real machines and '
       "addresses, the connections between them, and the GHOST probe tracing each alert. "
       "<b>Hover</b> a node for details, <b>click</b> one to lock onto it, <b>drag</b> to pan "
       "and <b>scroll</b> to zoom.</div>")
    attack_map()


# ---------------------------------------------------------------- activity chart
ui('<div class="h">Activity timeline</div>')
with st.container(key="timeline"):
    ui(f'<div class="cap">{esc(ctx.get("chart_note", ""))} Can you spot the attack without '
       "the agent? <b>Hover</b> for details, <b>scroll</b> to zoom, <b>drag</b> to pan, "
       "<b>double-click</b> to reset, and click a legend item to isolate it. Dashed lines mark "
       "the alerts.</div>")
    long = pivot[cols].reset_index().melt("bucket", var_name="Activity", value_name="Events")
    long = long[long.Events > 0].copy()
    # Stack the bars ourselves (each kind sits on top of the previous ones) and give each
    # bar the full width of its time bucket, so the chart can zoom smoothly.
    long["order"] = long.Activity.map({c: i for i, c in enumerate(cols)})
    long = long.sort_values(["bucket", "order"])
    long["top"] = long.groupby("bucket").Events.cumsum()
    long["base"] = long.top - long.Events
    step = pd.Timedelta(freq)
    long["start"] = long.bucket + step * 0.08
    long["end"] = long.bucket + step * 0.92
    pick = alt.selection_point(fields=["Activity"], bind="legend")
    bars = alt.Chart(long).mark_rect(cornerRadiusTopLeft=1, cornerRadiusTopRight=1).encode(
        x=alt.X("start:T", title=None),
        x2="end:T",
        y=alt.Y("base:Q", title=None),
        y2="top:Q",
        color=alt.Color("Activity:N", sort=cols,
                        scale=alt.Scale(domain=cols, range=[KINDS[c] for c in cols]),
                        legend=alt.Legend(orient="bottom", title=None, symbolType="square")),
        opacity=alt.condition(pick, alt.value(0.95), alt.value(0.12)),
        tooltip=[alt.Tooltip("bucket:T", title="From", format="%b %d %H:%M:%S"),
                 alt.Tooltip("Activity:N"), alt.Tooltip("Events:Q")],
    ).add_params(pick)
    marks = pd.DataFrame([{"time": pd.to_datetime(a.get("time"), errors="coerce"),
                           "Alert": a["id"], "Severity": a["severity"],
                           "Verdict": verdict_text(a), "What": a["summary"],
                           "row": 2 + 13 * (i % 3)} for i, a in enumerate(alerts)])
    marks = marks.dropna(subset=["time"]) if len(marks) else marks
    layers = [bars]
    if len(marks):
        sev_scale = alt.Scale(domain=list(SEV_HEX), range=list(SEV_HEX.values()))
        tips = ["Alert:N", "Severity:N", "Verdict:N", "What:N",
                alt.Tooltip("time:T", title="Time", format="%b %d %H:%M:%S")]
        layers += [
            alt.Chart(marks).mark_rule(strokeDash=[4, 3], strokeWidth=1.6).encode(
                x="time:T", color=alt.Color("Severity:N", scale=sev_scale, legend=None),
                tooltip=tips),
            alt.Chart(marks).mark_text(dx=4, align="left", baseline="top", fontSize=10,
                                       font="JetBrains Mono, ui-monospace, monospace").encode(
                x="time:T", y=alt.Y("row:Q", scale=None, axis=None), text="Alert:N",
                color=alt.Color("Severity:N", scale=sev_scale, legend=None), tooltip=tips),
        ]
    chart = (alt.layer(*layers).resolve_scale(color="independent")
             .properties(height=250, background="transparent")
             .configure_view(strokeWidth=0)
             .configure_axis(gridColor="rgba(140,170,190,.10)", domainColor="rgba(140,170,190,.25)",
                             labelColor="#7f909b", tickColor="rgba(140,170,190,.25)",
                             labelFont="JetBrains Mono, ui-monospace, monospace", labelFontSize=10)
             .configure_legend(labelColor="#b9c6ce", labelFont="IBM Plex Sans, system-ui, sans-serif", labelFontSize=11)
             .interactive(bind_y=False))
    st.altair_chart(chart, use_container_width=True, theme=None)


# ---------------------------------------------------------------- live run
live_map = None  # set while a live run is drawing the attack map


def run_live():
    prior = []
    todo = alerts
    if scenario == UPLOAD and PUBLIC and mode.startswith("Nemotron") and len(alerts) > MAX_UPLOAD_ALERTS:
        todo = sorted(alerts, key=lambda a: SEV_RANK.get(a["severity"], 9))[:MAX_UPLOAD_ALERTS]
        st.caption(f"Investigating the {MAX_UPLOAD_ALERTS} most severe of {len(alerts)} alerts "
                   "to keep the shared demo affordable. Run GHOST locally to investigate all.")
    for alert in todo:
        if live_map is not None:  # point the attack map at the alert being investigated
            with live_map.container():
                attack_map(focus=alert["id"], height=380)
        model = MockModel() if mode.startswith("Practice") else NIMModel()
        with st.status(f"🔎 Investigating {alert['id']}: {alert['summary']}",
                       expanded=True) as status:
            def show_step(t):
                ui(f'<div class="step"><span class="sn">{t["step"]}</span><span class="tool">'
                   f'{esc(t["tool"])}</span><span class="res">{esc(t.get("summary", t["args"]))}'
                   '</span></div>')
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
    ui('<div class="h">Live investigation</div>')
    live_map = st.empty()
    run_live()
    st.rerun()  # redraw the page with the finished results


# ---------------------------------------------------------------- attack chain
if confirmed:
    ui('<div class="h">Reconstructed attack chain</div>')
    stages = "".join(
        f'<a class="stage" href="#card-{esc(r["alert_id"])}"><div class="node"><span class="num">'
        f'{i + 1}</span><span class="wire"></span></div><div class="card"><div class="t">'
        f'{esc(r.get("title", r["alert_id"]))}</div>'
        + "".join(f'<span class="chip"><code>{esc(t)}</code>{esc(technique_name(t))}</span>'
                  for t in r.get("mitre", []))
        + f'<div class="go">Jump to {esc(r["alert_id"])} ↓</div></div></a>'
        for i, r in enumerate(confirmed))
    ui(f'<div class="chain">{stages}</div>')


# ---------------------------------------------------------------- alert cards
benign = {b["alert_id"]: b for b in scenarios.benign_results(truth, alerts, ss.reports)}

FILTERS = {"All": lambda a: True,
           "Attacks": lambda a: verdict_cls(a) == "tp",
           "False alarms": lambda a: verdict_cls(a) == "fp",
           "Needs review": lambda a: verdict_cls(a) == "nr",
           "Not investigated": lambda a: verdict_cls(a) == ""}
head_l, head_r = st.columns([1, 2.4], vertical_alignment="bottom")
head_l.markdown(f'<div class="h">Alerts<span class="n">{len(alerts)}</span></div>',
                unsafe_allow_html=True)
with head_r:
    show = st.segmented_control(
        "Show alerts", list(FILTERS), default="All", key="alert_filter",
        label_visibility="collapsed",
        format_func=lambda f: f if f == "All" else f"{f} ({sum(map(FILTERS[f], alerts))})")
if not reports and not run:
    ui('<div class="empty">Press <b>▶ Run live investigation</b> in the sidebar to watch the '
       "agent work.</div>")

for a in alerts:
    if not FILTERS.get(show or "All", FILTERS["All"])(a):
        continue
    r = ss.reports.get(a["id"])
    sev = a["severity"]
    with st.container(key=f"sev-{sev}-{a['id']}"):
        head = (f'<div class="anchor" id="card-{esc(a["id"])}"></div>'
                f'<div class="aid"><span class="sev {esc(sev)}">{esc(sev.capitalize())}</span>'
                f'<span class="id">{esc(a["id"])}</span>'
                f'<span class="type">{esc(a["type"].replace("_", " "))}</span></div>'
                f'<div class="asum">{esc(a["summary"])}</div>')
        if not r:
            ui(f'<div class="ahead"><div>{head}</div>'
               '<span class="pending">Not investigated yet</span></div>')
            continue
        v_cls, v_text = VERDICT_LABEL.get(r.get("verdict"), ("nr", r.get("verdict", "")))
        conf = r.get("confidence")
        meter = ""
        if isinstance(conf, (int, float)):
            pct = max(0, min(int(conf), 100))
            meter = (f'<div class="ring" style="--p:{pct}" title="Confidence {conf}%">'
                     f'<span>{conf}%<small>confidence</small></span></div>')
        answer = ""
        if a["id"] in benign:
            b = benign[a["id"]]
            answer = (f'<div class="key {"ok" if b["correct"] else "bad"}">Answer key: legitimate '
                      f'activity. {esc(b["note"])} — GHOST said <b>{esc(r.get("verdict"))}</b> '
                      f'({"correct" if b["correct"] else "wrong"}).</div>')
        link = str(r.get("related_to_prior") or "").strip()
        empty = ("null", "none", "n/a", "no ", "not ", "first alert")  # models write these as text
        linked = ""
        if link and not link.lower().startswith(empty) and "is the first al" not in link.lower():
            linked = f'<div class="linked">🔗 Linked to earlier alerts: {esc(link)}</div>'
        ui(f'''<div class="ahead"><div>{head}</div><div class="verdict" style="--vc:{VERDICT_HEX[v_cls]}">
            <span class="vlabel">{esc(v_text)}</span>{meter}</div></div>{answer}
            <div class="finding"><h4>{esc(r.get('title', ''))}</h4>
            <div class="stxt">{esc(r.get('summary', r.get('raw', '')))}</div>{linked}</div>''')

        acts = r.get("recommended_actions", [])
        pending = sum(1 for i in range(len(acts)) if not ss.decisions.get(f"{a['id']}:{i}"))
        trace = r.get("trace", [])
        tab_ev, tab_act, tab_trail = st.tabs([
            f"Evidence & MITRE ({len(r.get('evidence', []))})",
            f"Recommended actions ({len(acts)})",  # labels stay fixed so the open tab survives clicks
            f"Investigation trail ({len(trace)} tool calls, {r.get('seconds', '?')}s)"])
        with tab_ev:
            ev = "".join(f'<li data-n="{i + 1:02d}">{esc(e)}</li>'
                         for i, e in enumerate(r.get("evidence", [])))
            block = f'<ul class="ev">{ev}</ul>' if ev else ""
            if r.get("mitre"):
                block += ('<div class="lbl">MITRE ATT&amp;CK <span>click a technique to open it '
                          f'on attack.mitre.org</span></div>{mitre_chips(r["mitre"])}')
            if r.get("candidate_mitre"):
                block += ('<div class="note">🔍 Possible, suggested by the full MITRE ATT&amp;CK '
                          "search but not tied to evidence, so not counted:</div>"
                          + mitre_chips(r["candidate_mitre"], "dim"))
            if r.get("unverified_mitre"):
                block += ('<div class="note">⚠️ Rejected by grounding check (claimed without '
                          "evidence):</div>" + "".join(
                              f'<span class="chip bad"><code>{esc(t)}</code></span>'
                              for t in r["unverified_mitre"]))
            ui(block)
        with tab_act:
            ui(f'<div class="lbl">A human must approve each action before anything happens. '
               f'<span>{pending} of {len(acts)} awaiting a decision.</span></div>')
            for i, act in enumerate(acts):
                key = f"{a['id']}:{i}"
                row = st.columns([5, 1.1, 1], gap="small", vertical_alignment="center")
                label = act.get("action", str(act)) if isinstance(act, dict) else str(act)
                target = act.get("target", "") if isinstance(act, dict) else ""
                prio = act.get("priority", "") if isinstance(act, dict) else ""
                decision = ss.decisions.get(key)
                mark = (f'<span class="done {decision}">{decision.capitalize()}</span>'
                        if decision else "")
                row[0].markdown(
                    f'<div class="act {decision or ""}">{mark}<span class="txt">{esc(label)}</span>'
                    + (f" <code>{esc(target)}</code>" if target else "")
                    + (f'<span class="pri {esc(prio)}">{esc(prio)}</span>' if prio else "")
                    + "</div>", unsafe_allow_html=True)
                if not decision:
                    if row[1].button("Approve", key=f"ok-{key}"):
                        ss.decisions[key] = "approved"
                        st.rerun()
                    if row[2].button("Reject", key=f"no-{key}"):
                        ss.decisions[key] = "rejected"
                        st.rerun()
        with tab_trail:
            tools = {t["tool"] for t in trace}
            ui(f'<div class="trailhead"><span><b>{len(trace)}</b> tool calls</span>'
               f'<span><b>{len(tools)}</b> different tools</span>'
               f'<span><b>{esc(r.get("seconds", "?"))}s</b> total</span></div>')
            for t in trace:
                found = t.get("summary") or summarize_step(t["tool"], t["args"], t["result_preview"])
                step = st.columns([10, 2.3], vertical_alignment="center")
                step[0].markdown(f'<div class="step"><span class="sn">{t["step"]}</span>'
                                 f'<span class="tool">{esc(t["tool"])}</span>'
                                 f'<span class="res">{esc(found)}</span></div>',
                                 unsafe_allow_html=True)
                with step[1].popover("Raw tool output"):
                    st.code(t["result_preview"], language="json", wrap_lines=True)
