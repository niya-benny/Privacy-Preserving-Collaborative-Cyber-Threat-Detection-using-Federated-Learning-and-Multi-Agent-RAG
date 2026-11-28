"""STEP 7b - add OFFICIAL MITRE ATT&CK text to the knowledge base.
For every technique ID listed in kb/global/*.md this writes kb/mitre/<id>.md containing MITRE's own name, description
(first paragraph), tactic and listed mitigations. Then rebuild the index:  python s7_build_kb.py --index-only
Needs data/mitre/enterprise-attack.json (download instructions in the chat / README).   Usage: python s7b_add_mitre.py
"""
import json, re, sys
from collections import defaultdict
from config import KB_DIR, ROOT

SRC = ROOT / "data" / "mitre" / "enterprise-attack.json"
ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def clean_md(t):
    t = re.sub(r"\(Citation: .*?\)", "", t)            # MITRE's inline citations
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)      # markdown links -> link text
    t = re.sub(r"<[^>]+>", "", t)                       # <code> etc.
    return re.sub(r"[ \t]+", " ", t).strip()


def shorten(t, n):
    if len(t) <= n:
        return t
    cut = t[:n]
    k = cut.rfind(". ")
    return cut[:k + 1] if k > n * 0.4 else cut.rsplit(" ", 1)[0] + "..."


def ids_from_kb():
    """technique id -> set of attack classes that list it in kb/global/*.md"""
    out = defaultdict(set)
    for f in sorted((KB_DIR / "global").glob("*.md")):
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", f.read_text(encoding="utf-8"), re.S)
        if not m:
            continue
        attacks = [a.strip() for l in m.group(1).splitlines() if l.startswith("attack_types:") for a in l.split(":", 1)[1].split(",")]
        if attacks == ["ALL"]:
            continue
        line = re.search(r"Relevant techniques:([^\n]*)", m.group(2))
        for tid in (ID.findall(line.group(1)) if line else []):
            out[tid].update(attacks)
    return out


def main():
    if not SRC.exists():
        sys.exit(f"Missing {SRC}. Download enterprise-attack.json first (see the instructions).")
    want = ids_from_kb()
    if not want:
        sys.exit("No technique IDs found in kb/global/*.md - run python s7_build_kb.py first.")
    objs = json.load(open(SRC, encoding="utf-8"))["objects"]
    col = next((o for o in objs if o.get("type") == "x-mitre-collection"), {})
    print("ATT&CK dataset:", col.get("name", "?"), "| version:", col.get("x_mitre_version", "not stated in file"), "(cite this in the paper)\n")
    by_ref = {o["id"]: o for o in objs if "id" in o}
    live = lambda o: not (o.get("revoked") or o.get("x_mitre_deprecated"))
    ext = lambda o: next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
    tech = {ext(o): o for o in objs if o.get("type") == "attack-pattern" and live(o) and ext(o)}
    mit = defaultdict(list)
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates" and live(o):
            s = by_ref.get(o["source_ref"])
            if s and s.get("type") == "course-of-action" and live(s):
                mit[o["target_ref"]].append(f"{s['name']} ({ext(s)})")
    out_dir = KB_DIR / "mitre"
    out_dir.mkdir(exist_ok=True)
    for f in out_dir.glob("*.md"):
        f.unlink()
    print(f"{'ID':10}{'official MITRE name':45}classes")
    for tid in sorted(want):
        o = tech.get(tid)
        if o is None:
            print(f"{tid:10}NOT FOUND in this dataset (revoked, deprecated or wrong ID) - check it on attack.mitre.org")
            continue
        desc = shorten(clean_md(o.get("description", "").split("\n\n")[0]), 480)
        tactics = ", ".join(p["phase_name"].replace("-", " ") for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack")
        mits = mit.get(o["id"]) or mit.get(tech.get(tid.split(".")[0], {}).get("id"), [])
        second = shorten(f"Tactic: {tactics or 'not stated'}." + (f" Mitigations listed by MITRE: {', '.join(sorted(set(mits))[:5])}." if mits else ""), 300)
        classes = ", ".join(sorted(want[tid]))
        head = f"institution: global\ndocument_type: MITRE_ATTACK\ntopic: {tid}\nattack_types: {classes}\nmitre: {tid}\nsource: MITRE ATT&CK (c) The MITRE Corporation"
        (out_dir / f"{tid.replace('.', '_')}.md").write_text(f"---\n{head}\n---\nMITRE ATT&CK {tid} {o['name']}. {desc}\n\n{second}\n", encoding="utf-8")
        print(f"{tid:10}{o['name'][:43]:45}{classes}")
    print(f"\nWrote {len(list(out_dir.glob('*.md')))} documents to {out_dir}. Next: python s7_build_kb.py --index-only")


if __name__ == "__main__":
    main()
