"""STEP 8 - Multi-Agent RAG incident reports for the incidents created by the mitigation replay.
Needs Ollama running locally with the model pulled (ollama pull llama3:8b).
Usage: python s8_generate_reports.py --n 12 [--fast]     (--fast: attack-analysis agent is rule-based -> fewer LLM calls)
"""
import argparse, json, collections
from config import ART, OUT
from common import load_meta
from rag.kb import KnowledgeBase
from rag.agents import Pipeline


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=12); ap.add_argument("--fast", action="store_true")
    a = ap.parse_args()
    inc = json.load(open(ART / "incidents.json"))
    by = collections.defaultdict(list)
    for x in inc: by[x["predicted_class"]].append(x)
    pick = []                                           # round-robin over attack classes so every class is represented
    while len(pick) < min(a.n, len(inc)):
        for c in list(by):
            if by[c] and len(pick) < a.n: pick.append(by[c].pop(0))
    pipe = Pipeline(KnowledgeBase.load(), load_meta()["classes"], use_llm_for_analysis=not a.fast)
    (OUT / "reports").mkdir(exist_ok=True)
    md = ["# Generated incident reports\n"]
    for i, al in enumerate(pick):
        print(f"[{i + 1}/{len(pick)}] {al['institution']} {al['predicted_class']} {al['src_ip']}", flush=True)
        r = pipe.generate(al)
        r.pop("chunks", None)
        json.dump({"alert": al, **r}, open(OUT / "reports" / f"report_{i + 1:02d}.json", "w"), indent=1)
        if r["status"] == "rejected":
            continue
        rep = r["report"]
        md += [f"## Incident {i + 1}: {rep['attack_type']} at {rep['institution']} (status: {r['status']})",
               f"**Source:** {rep['source_ip']}  |  **Confidence:** {rep['confidence']}  |  **Faithfulness:** {r['checks']['faithfulness']}\n",
               f"**Summary:** {rep['summary']}\n", f"**Impact:** {rep['impact']}\n", f"**MITRE:** {', '.join(rep['mitre_techniques'])}\n" + "".join(f"- {d['id']} {d['name']}: {d['description']}\n" for d in rep.get("technique_details", [])),
               "**Response steps:**"] + [f"{j + 1}. {s}" for j, s in enumerate(rep["response_steps"])] + \
              [f"\n**Escalation:** {rep.get('escalation', '')}", f"*Sources: {', '.join(r['sources'])}*\n"]
    (OUT / "reports.md").write_text("\n".join(md), encoding="utf-8")
    print("Done -> outputs/reports/ and outputs/reports.md")


if __name__ == "__main__":
    main()
