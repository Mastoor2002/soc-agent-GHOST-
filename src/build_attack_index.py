"""
STEP 10 — Build GHOST's MITRE ATT&CK index (the "RAG" knowledge base).

WHY: The agent used to know 17 hand-picked techniques. Real attacks use any of the
~700 in MITRE ATT&CK, so this script turns MITRE's official dataset into a small
JSON file the agent can search: every technique's ID, name, tactics, platforms, a
short description, and the mitigations MITRE links to it.

Run once (needs internet; the result is committed to the repo):
    python -m src.build_attack_index

Source: MITRE ATT&CK Enterprise, STIX 2.1, https://github.com/mitre-attack/attack-stix-data
ATT&CK is © The MITRE Corporation and used under its Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "enterprise-attack/enterprise-attack.json")
OUT = Path(__file__).resolve().parent.parent / "data" / "attack" / "enterprise_attack.json"


def clean(text: str, limit: int) -> str:
    """Drop citations and markdown links, keep the first couple of sentences."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"<code>|</code>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    return cut[: cut.rfind(". ") + 1] if ". " in cut else cut.rsplit(" ", 1)[0] + "..."


def attack_id(obj) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build(stix: dict) -> dict:
    objs = stix["objects"]
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    patterns = {o["id"]: o for o in objs if o["type"] == "attack-pattern" and live(o)}
    mitigations = {o["id"]: o["name"] for o in objs if o["type"] == "course-of-action" and live(o)}

    mitigated_by = {}
    for r in objs:
        if (r["type"] == "relationship" and r.get("relationship_type") == "mitigates"
                and r.get("source_ref") in mitigations and r.get("target_ref") in patterns):
            mitigated_by.setdefault(r["target_ref"], []).append(mitigations[r["source_ref"]])

    by_id = {attack_id(p): p for p in patterns.values() if attack_id(p)}
    techniques = {}
    for tid, p in sorted(by_id.items()):
        name = p["name"]
        if "." in tid and tid.split(".")[0] in by_id:  # 'PowerShell' -> 'Command and ...: PowerShell'
            name = f"{by_id[tid.split('.')[0]]['name']}: {name}"
        techniques[tid] = {
            "name": name,
            "tactics": [k["phase_name"].replace("-", " ").title()
                        for k in p.get("kill_chain_phases", [])
                        if k.get("kill_chain_name") == "mitre-attack"],
            "platforms": p.get("x_mitre_platforms", []),
            "summary": clean(p.get("description", ""), 420),
            "mitigations": sorted(set(mitigated_by.get(p["id"], [])))[:4],
        }
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), None)
    return {"source": URL, "attack_version": version, "count": len(techniques),
            "license": "MITRE ATT&CK, (c) The MITRE Corporation, ATT&CK Terms of Use",
            "techniques": techniques}


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path:
        stix = json.loads(Path(path).read_text(encoding="utf-8"))
    else:
        print(f"Downloading {URL} (about 55 MB) ...")
        with urllib.request.urlopen(URL) as r:
            stix = json.loads(r.read())
    index = build(stix)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(index, indent=0, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {OUT.relative_to(OUT.parent.parent.parent)}: {index['count']} techniques, "
          f"ATT&CK v{index['attack_version']}, {OUT.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
