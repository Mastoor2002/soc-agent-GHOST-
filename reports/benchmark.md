| Scenario | Events | Alerts | Answer key | Detection | Agent | Confirmed | Legit activity dismissed | Agent time |
|---|---|---|---|---|---|---|---|---|
| Practice attack (synthetic) | 1,270 | 3 | T1021, T1048, T1078, T1110 | 3/4 | 4/4 | 3/3 | — | 32s |
| Real attack: Mimikatz LogonPasswords (OTRF) | 6,015 | 2 | T1003.001 | 1/1 | 1/1 | 2/2 | — | 18s |
| Real attack: Empire Invoke-PsExec (OTRF) | 4,335 | 3 | T1021 | 1/1 | 1/1 | 3/3 | — | 36s |
| Real attack: Empire Invoke-SMBExec (OTRF) | 7,489 | 4 | T1021.002 | 1/1 | 1/1 | 3/4 | 1/1 | 38s |
| Real attack: Empire Invoke-WMI (OTRF) | 6,352 | 3 | T1047 | 1/1 | 1/1 | 3/3 | — | 54s |

**Detection coverage:** 7/8 answer-key techniques across 5 scenarios, 25,461 events.
**Agent coverage (nim):** 8/8. Hallucinated techniques rejected by grounding check: 0. Reports fixed by self-correction: 1.

Model: `nvidia/Nemotron-3_5-Lightning` via Nebius Token Factory
