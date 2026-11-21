"""Minimal client for a LOCAL Ollama server (no data leaves the machine). Uses only the standard library."""
import json, time, urllib.request
from config import OLLAMA_URL, LLM_MODEL, NUM_CTX


def chat(system, user, json_mode=True, max_tokens=300, model=LLM_MODEL, temperature=0.0):
    body = {"model": model, "stream": False, "keep_alive": "10m",
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": temperature, "num_ctx": NUM_CTX, "num_predict": max_tokens, "seed": 42}}
    if json_mode:
        body["format"] = "json"
    req = urllib.request.Request(OLLAMA_URL + "/api/chat", json.dumps(body).encode(), {"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=600) as r:
        d = json.loads(r.read())
    return d["message"]["content"], {"latency_s": round(time.time() - t0, 2), "prompt_tokens": d.get("prompt_eval_count", 0),
                                     "output_tokens": d.get("eval_count", 0)}
