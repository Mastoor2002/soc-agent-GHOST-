# 👻 GHOST — Generative Hunting & Operations Security Toolkit

An AI security analyst that hunts attacks in your logs, investigates them like a human expert with **NVIDIA Nemotron** (served through **Nebius Token Factory** or **NVIDIA NIM**), and recommends fixes that a human approves. Detection is written to run GPU-accelerated via **RAPIDS**.

Tested on a synthetic attack **and on real attack recordings** from the [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) project.

Built for the Nebius x NVIDIA Global AI Hackathon (deadline: Oct 30, 2026).

---

## How it works (the big picture)

```
 logs.jsonl ──► replay ──► DETECT (fast, GPU) ──► alerts ──► AGENT (smart, LLM) ──► incident reports
  1,000s of       live        rules + stats         3            Nemotron + tools       verdict, MITRE,
  events         stream       scan everything                    investigates each      evidence, actions
```

**Why two layers?** An LLM is too slow and expensive to read millions of log lines. So cheap detection code scans *everything* and flags a few suspicious things. The LLM then investigates *only those*. Every real SOC tool works this way.

---

## Quick start

```bash
# 1. Set up a virtual environment (keeps packages isolated)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. (Optional) re-create the data — both scenarios already ship in data/
python -m src.generate_logs        # practice attack  -> data/synthetic/
python -m src.load_otrf            # real attack      -> data/real_psexec/

# 3. Run everything with the fake model first — no API key needed
python -m src.main --mock
python -m src.main --mock --scenario real_psexec

# 4. Get a free key at https://build.nvidia.com, then:
cp .env.example .env               # paste your key into .env
python -m src.main --scenario real_psexec   # now the real Nemotron investigates
```

## Scenarios

| Scenario | Events | What's hidden in it | Answer key |
|---|---|---|---|
| `synthetic` | 1,270 | VPN brute force → lateral movement → 2.5 GB exfiltration, plus a false-positive trap (big internal backup) | 4 techniques we planted |
| `real_psexec` | 4,335 | Empire **Invoke-PsExec**: remote logon → fake "Updater" service → encoded PowerShell stager → callback | OTRF label **T1021** |
| `real_smbexec` | 7,489 | Empire **Invoke-SMBExec**: same idea over SMB named pipes. Also contains Azure's legitimate guest agent reading lsass memory, which GHOST must *not* call an attack | OTRF label **T1021.002** + 1 legitimate activity |
| `real_wmi` | 6,352 | Empire **Invoke-WMI**: code run remotely through WMI, with no service created | OTRF label **T1047** |
| `real_mimikatz` | 6,015 | **Mimikatz** reading passwords out of lsass.exe memory | OTRF label **T1003.001** |

Real scenarios come from the [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets): attacks run with real tools in a lab Windows domain. The answer key is each dataset's official label, not ours.

## Benchmark

First Nebius run (October 5, 2026), `nvidia/Nemotron-3_5-Lightning` via **Nebius Token Factory**:

| Scenario | Events | Answer key | Detection | Agent | Agent time |
|---|---|---|---|---|---|
| Practice attack (synthetic) | 1,270 | T1021, T1048, T1078, T1110 | 3/4 | 4/4 | 28 s |
| Mimikatz LogonPasswords (OTRF) | 6,015 | T1003.001 | 1/1 | 1/1 | 17 s |
| Empire Invoke-PsExec (OTRF) | 4,335 | T1021 | 1/1 | 1/1 | 30 s |
| Empire Invoke-SMBExec (OTRF) | 7,489 | T1021.002 | 1/1 | 1/1 | 40 s |
| Empire Invoke-WMI (OTRF) | 6,352 | T1047 | 1/1 | 1/1 | 32 s |

8/8 answer-key techniques, 0 hallucinated techniques, and the legitimate Azure agent correctly dismissed as a false positive. The same model on NVIDIA's free endpoint (October 3) also scored 8/8 but took 1,312 s of agent time, against 147 s on Nebius. A later run that night, after tightening the grounding check, scored the same 8/8 in 178 s.

**Choosing a provider:** GHOST talks to any OpenAI-compatible endpoint. Set `NIM_BASE_URL`, `NIM_MODEL` and the matching key in `.env` (see `.env.example` for NVIDIA and Nebius settings). No code changes.

```bash
python -m src.benchmark                 # detection only, instant
python -m src.benchmark --agent nim     # + Nemotron investigating every alert
```
Writes `reports/benchmark.md`, a results table across all scenarios.

**Honest history:** when we first ran the detectors built for PsExec on the three new real attacks, they caught SMBExec (a variant) unchanged, caught only the side effects of the WMI attack, and **missed the Mimikatz password theft entirely**. That's why the WMI and LSASS detectors exist.

Each scenario is a folder in `data/` with `logs.jsonl`, `ground_truth.json` (never read by detectors or the agent), and `context.json` (company IP ranges, employee directory, threat intel).

### Dashboard

```bash
streamlit run dashboard.py
```
Opens a web page at http://localhost:8501. Press **▶ Run live investigation** to watch the agent work.

---

## Read the code in this order

Every file starts with a "WHY" comment explaining the concept. Read them in order:

| # | File | What you'll learn |
|---|------|-------------------|
| 1 | `src/generate_logs.py` | What security logs look like, and how a real attack chain shows up in them |
| 1b | `src/load_otrf.py` | Real Windows event logs, and *normalizing* them into one schema |
| 1c | `src/scenarios.py` | Organizing test cases, and fair scoring against an answer key |
| 2 | `src/replay.py` | Streaming data with Python generators (`yield`) |
| 3 | `src/detect.py` | Detection engineering: turning logs into alerts with pandas (8 detectors) |
| 4 | `src/tools.py` | **Tool calling**: how an LLM "does things" safely, including decoding hidden PowerShell |
| 5 | `src/agent.py` | **The agent loop**: the core pattern behind every AI agent |
| 6 | `src/main.py` | Wiring it together, plus scoring against the answer key |
| 7 | `dashboard.py` | Streamlit web dashboard: live investigation, attack chain, human approval |
| 8 | `src/benchmark.py` | Evaluating a security tool across many attacks: coverage *and* false positives |

**Try this:** run individual steps on their own (`python -m src.detect`, `python -m src.replay`) and change the thresholds in `detect.py` to see what happens.

---

## Key concepts, in plain English

**The attack we planted** (look at `data/synthetic/ground_truth.json`):
1. **Brute force (T1110):** an outside IP guesses `jsmith`'s VPN password 37 times, then gets in.
2. **Lateral movement (T1021):** the attacker hops from server to server using that account.
3. **Exfiltration (T1048):** 2.5 GB of data is sent to an outside server at 3 AM.

There's also a **trap**: a nightly 2.4 GB backup. It's a big transfer but legitimate, because it goes to an internal address. A good system must *not* flag it, and that's how you show a low false-positive rate.

**The real attack** (`real_psexec`), as Windows recorded it:
1. User `pgustavo` on WORKSTATION5 logs in over the network to WORKSTATION6.
2. A new Windows service named **"Updater"** appears there. It's a disguise: the service runs `cmd.exe`.
3. That launches PowerShell with an **encoded (base64) command**. GHOST's `decode_command` tool reveals it disables PowerShell security logging, bypasses the AMSI antivirus scan (with the text chopped up like `'Amsi'+'Utils'` to dodge scanners), and downloads more code from `http://10.10.10.5`.
4. PowerShell, running as SYSTEM, connects to `10.10.10.5:80`, an address outside the company's network ranges.
5. The attacker runs `whoami` to check what access they got.

Only 18 of the 4,335 events matter. The rest is normal Windows background noise.

**MITRE ATT&CK** is the industry's shared dictionary of attacker techniques (T1110 = Brute Force). Mapping findings to it makes your tool speak the same language as real SOC teams.

**NIM** is NVIDIA's way to serve AI models. It speaks the same API as OpenAI, so we use the normal `openai` library and just change `base_url`. You can use NVIDIA's hosted endpoint, or run NIM yourself on a Nebius GPU, with a one-line config change.

**Tool calling:** we describe our Python functions to the model in JSON. The model replies "call `ip_reputation` with ip=X", our code runs it, and we send the result back. The model can *only* request the functions we define, so it can never touch the system directly.

**`cudf.pandas`** (RAPIDS) runs normal pandas code on an NVIDIA GPU with zero code changes:
```bash
pip install cudf-cu12 --extra-index-url=https://pypi.nvidia.com   # on a GPU machine
python -m cudf.pandas -m src.main
```

---

## Roadmap to Oct 30

- [x] **Week 1: Foundation.** Data, replay, detection, tools, agent loop, scoring *(this starter)*
- [x] **Real agent.** Nemotron via NIM; prompt tuned from 2/4 to 4/4 on the synthetic attack
- [x] **Real data.** OTRF Empire PsExec recording, with Windows log normalization, 3 new detectors, and a PowerShell decoder tool
- [x] **More real data.** 4 OTRF recordings (PsExec, SMBExec, WMI, Mimikatz), WMI and LSASS detectors, a real-world false-positive check, and a benchmark across all scenarios
- [x] **Guardrails.** Self-correction for unreadable reports; grounding check that rejects techniques the AI claims without evidence
- [ ] **Week 3: GPU proof.** Scale logs to millions of rows; benchmark pandas (CPU) vs `cudf.pandas` (GPU) on Nebius
- [ ] **Week 3: RAG.** Replace the mini MITRE table with vector search over the full ATT&CK dataset
- [x] **Dashboard.** Live investigation view, attack chain, human-approved actions *(done early)*
- [ ] **Week 4: Polish.** Metrics (accuracy, false positives, time to triage), a 3-minute demo video, and the submission

---

## Project layout

```
soc-agent/
├── data/
│   ├── synthetic/          # practice attack: logs.jsonl, ground_truth.json, context.json
│   └── real_psexec/        # real recorded attack (OTRF), same three files
├── reports/                # agent output, one file per scenario
├── src/                    # the code, read in order 1–6
├── requirements.txt
└── .env.example            # copy to .env and add your NVIDIA key
```
