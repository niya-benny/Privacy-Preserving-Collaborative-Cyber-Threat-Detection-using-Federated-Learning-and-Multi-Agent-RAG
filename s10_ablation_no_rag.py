"""STEP 10 (optional but valuable) - ABLATION: does retrieval actually help?
Same 12 incidents, same local Llama, but WITHOUT the knowledge base. Both settings are scored with the same yardstick
(the knowledge-base documents for that attack class / institution). Needs Ollama running.   Usage: python s10_ablation_no_rag.py
"""
import glob, json
import numpy as np
from config import OUT
from rag import guards, llm
from rag.agents import _json
from rag.kb import KnowledgeBase

SYS = ("You are a security analyst assistant for a university SOC. Write an incident report for the alert. "
       "Answer with a single JSON object and nothing else.")


def truth(kb, alert):
    a, inst = alert["predicted_class"], alert["institution"]
    g = [c for c in kb.chunks if c["institution"] == "global" and a in c["attack_types"]]
    p = [c for c in kb.chunks if c["institution"] == inst and a in c["attack_types"] and c["topic"] == "Incident_Response"]
    return g, p


def score(report, alert, g, p):
    rep = report if isinstance(report, dict) else {}
    ids = set(guards.MITRE.findall(json.dumps(rep)))
    kb_ids = set(guards.MITRE.findall(" ".join(c["text"] for c in g)))
    steps = [str(s) for s in rep.get("response_steps", [])] if isinstance(rep.get("response_steps"), list) else []
    pol = " ".join(c["text"] for c in p)
    exp = guards.extract_escalation(p)
    esc = json.dumps(rep.get("escalation", ""))
    ck = guards.check_report(rep, g, p)
    return {"mitre_valid": bool(ids) and ids <= kb_ids,
            "steps_supported": float(np.mean([guards.support(s, pol) >= 0.6 for s in steps])) if steps else 0.0,
            "contact_correct": bool(exp) and exp.split("(")[-1].strip(")") in esc,
            "faithfulness": ck["faithfulness"]}


def main():
    kb = KnowledgeBase.load()
    reps = [json.load(open(f)) for f in sorted(glob.glob(str(OUT / "reports" / "report_*.json")))]
    reps = [r for r in reps if r.get("status") != "rejected"]
    rows = {"With RAG (ours)": [], "No retrieval (LLM only)": []}
    raw = []
    for i, r in enumerate(reps):
        al = r["alert"]; g, p = truth(kb, al)
        rows["With RAG (ours)"].append(score(r["report"], al, g, p))
        user = (f"Alert: institution={al['institution']}; attack_class={al['predicted_class']}; confidence={al['confidence']}; "
                f"source_ip={al['src_ip']}.\nJSON keys: \"summary\", \"impact\", \"mitre_techniques\" (list of ATT&CK IDs), "
                "\"response_steps\" (list), \"escalation\" (who to contact).")
        text, _ = llm.chat(SYS, user, True, 320)
        raw.append({"alert": al, "output": text})
        rows["No retrieval (LLM only)"].append(score(_json(text), al, g, p))
        print(f"[{i + 1}/{len(reps)}] done", flush=True)
    res = {k: {m: round(float(np.mean([x[m] for x in v])), 3) for m in v[0]} for k, v in rows.items()}
    res["n_incidents"] = len(reps)
    json.dump(res, open(OUT / "results_ablation.json", "w"), indent=1)
    json.dump(raw, open(OUT / "ablation_no_rag_outputs.json", "w"), indent=1)
    print("\nABLATION (same incidents, same model)")
    for k in rows: print(f"{k:26}", res[k])


if __name__ == "__main__":
    main()
