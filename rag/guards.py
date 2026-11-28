"""Lightweight safety checks around the local Llama model (all plain Python, run on the laptop)."""
import json, re
from config import MAX_FIELD_CHARS

SPECIAL = re.compile(r"<\|[^|>]{0,40}\|>|\[/?INST\]|<<?/?SYS>>?|</?data>", re.I)   # Llama-3 / Llama-2 control tokens + our data tags
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
INJECTION = re.compile(r"ignore (all |any |the )?(previous|prior|above)|disregard .{0,30}instruction|system prompt|you are now|new instructions", re.I)
IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def clean(text, max_chars=MAX_FIELD_CHARS, keep_lines=False):
    """Strip special-token strings + control chars, collapse whitespace, cap length."""
    t = SPECIAL.sub("", str(text))
    t = CTRL.sub(" ", t)
    if keep_lines:                                     # knowledge-base chunks keep their bullet-list line breaks
        t = re.sub(r"[ \t]+", " ", t)
        return re.sub(r"\n\s*\n+", "\n", t).strip()[:max_chars]
    return re.sub(r"\s+", " ", t).strip()[:max_chars]


def validate_alert(alert, institutions, classes):
    """Alert fields must come from allowed values; anything else is rejected (not 'repaired')."""
    errs = []
    if alert.get("institution") not in institutions: errs.append("unknown institution")
    if alert.get("predicted_class") not in classes or alert.get("predicted_class") == "BENIGN": errs.append("invalid attack class")
    if not IP.match(str(alert.get("src_ip", ""))) or any(int(x) > 255 for x in str(alert.get("src_ip", "0.0.0.0")).split(".") if x.isdigit()):
        errs.append("invalid source IP")
    try:
        c = float(alert.get("confidence", 0))
        if not 0 <= c <= 1: errs.append("confidence out of range")
    except (TypeError, ValueError):
        errs.append("confidence not numeric")
    return errs


def safe_chunks(chunks, max_chars):
    """Drop chunks that look like prompt injection, clean + length-limit the rest."""
    out, dropped = [], 0
    for c in chunks:
        if INJECTION.search(c["text"]):
            dropped += 1
            continue
        out.append({**c, "text": clean(c["text"], max_chars, keep_lines=True)})
    return out, dropped


def est_tokens(text):
    return int(len(text) / 3.5) + 1


def _toks(s):
    return set(re.findall(r"[a-z0-9]{4,}", s.lower()))


def support(sentence, context_text):
    t = _toks(sentence)
    return len(t & _toks(context_text)) / len(t) if t else 1.0


REQUIRED = ("summary", "impact", "mitre_techniques", "response_steps")


def check_report(report, global_ctx, policy_ctx, step_thr=0.6):
    """Compare the generated report against the retrieved sources. Returns a dict of checks."""
    res = {"structure_ok": isinstance(report, dict) and all(k in report for k in REQUIRED)}
    if not res["structure_ok"]:
        res.update(mitre_grounded=False, ungrounded_ids=[], step_support=0.0, faithfulness=0.0, passed=False)
        return res
    ctx_all = " ".join(c["text"] for c in global_ctx + policy_ctx)
    ids_ctx = set(MITRE.findall(ctx_all))
    ids_rep = set(MITRE.findall(json.dumps(report)))
    ungrounded = sorted(ids_rep - ids_ctx)
    steps = [str(s) for s in report.get("response_steps", [])]
    pol = " ".join(c["text"] for c in policy_ctx)
    step_scores = [support(s, pol) for s in steps] or [0.0]
    imp = support(str(report.get("impact", "")), ctx_all)
    res.update(mitre_grounded=not ungrounded, ungrounded_ids=ungrounded,
               step_support=sum(s >= step_thr for s in step_scores) / len(step_scores),
               faithfulness=round((sum(step_scores) + imp) / (len(step_scores) + 1), 3))
    res["passed"] = res["mitre_grounded"] and res["step_support"] >= 0.8 and bool(steps) and imp >= 0.4
    return res


def summary_ok(summary, alert):
    """Numbers and IPs written in the summary must match the alert (the model sometimes rounds or invents them)."""
    c = float(alert["confidence"])
    allowed = {f"{c:.3f}".rstrip("0"), f"{c:.2f}", f"{int(c * 100) / 100:.2f}", f"{c:.1f}", alert["src_ip"]}
    found = re.findall(r"\d+\.\d+(?:\.\d+\.\d+)?", str(summary))
    return all(x in allowed for x in found)


ESC = re.compile(r"[Ee]scalate to the ([^()\n.]{3,60}?)\s*\((ext \d+)\)")


def extract_escalation(chunks):
    """Escalation contact copied straight from the institution's own playbook text (no LLM involved)."""
    for c in chunks:
        m = ESC.search(c["text"])
        if m:
            return f"{m.group(1)} ({m.group(2)})"
    return None


def mitre_details(chunks, ids):
    """Official MITRE ATT&CK name + first description sentence + listed mitigations for each technique id,
    copied by code from the knowledge-base chunks (no LLM involved)."""
    by = {c["topic"]: c["text"] for c in chunks if c.get("document_type") == "MITRE_ATTACK"}
    out = []
    for tid in (ids if isinstance(ids, list) else []):
        t = by.get(tid) if isinstance(tid, str) else None
        m = re.match(r"MITRE ATT&CK (T\d{4}(?:\.\d{3})?) (.+?)\. (.*)", t or "", re.S)
        if not m:
            continue
        first = re.split(r"(?<=[.!?])\s", m.group(3).split("\n")[0])[0]
        mit = re.search(r"Mitigations listed by MITRE: (.*)", t)
        out.append({"id": tid, "name": m.group(2), "description": first[:300],
                    "mitigations": mit.group(1).strip().rstrip(".") if mit else ""})
    return out
