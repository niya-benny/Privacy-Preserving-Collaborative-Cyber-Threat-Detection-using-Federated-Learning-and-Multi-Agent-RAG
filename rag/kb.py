"""Knowledge base: markdown docs -> chunks -> MiniLM embeddings -> FAISS index + metadata lookup table."""
import json, re
import numpy as np
from config import EMBED_MODEL, MAX_CHUNK_CHARS, ART, KB_DIR

_model = None


def embed(texts):
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(EMBED_MODEL, device="cpu")
    return np.asarray(_model.encode(list(texts), normalize_embeddings=True, convert_to_numpy=True), dtype="float32")


def parse_doc(text):
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    meta, body = {}, text
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1); meta[k.strip()] = v.strip()
        body = m.group(2)
    meta["attack_types"] = [a.strip() for a in meta.get("attack_types", "ALL").split(",")]
    return meta, body.strip()


def chunk_text(body, max_chars=MAX_CHUNK_CHARS):
    paras, out, cur = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()], [], ""
    for p in paras:
        if cur and len(cur) + len(p) > max_chars:
            out.append(cur); cur = p
        else:
            cur = (cur + "\n" + p).strip()
    return out + ([cur] if cur else [])


class _NumpyIndex:                      # tiny fallback so the code still runs where faiss is not installed
    def __init__(self, dim): self.v = np.zeros((0, dim), "float32")
    def add(self, x): self.v = np.vstack([self.v, x])
    def search(self, q, k):
        s = q @ self.v.T; ids = np.argsort(-s, axis=1)[:, :k]
        return np.take_along_axis(s, ids, 1), ids


def make_index(vecs):
    try:
        import faiss
        idx = faiss.IndexFlatIP(vecs.shape[1])
    except ImportError:
        idx = _NumpyIndex(vecs.shape[1])
    idx.add(vecs)
    return idx


class KnowledgeBase:
    def __init__(self, embed_fn=embed):
        self.chunks, self.index, self.embed = [], None, embed_fn

    def build(self, kb_dir=KB_DIR):
        for f in sorted(kb_dir.rglob("*.md")):
            meta, body = parse_doc(f.read_text(encoding="utf-8"))
            for i, t in enumerate(chunk_text(body)):
                self.chunks.append({"id": f"{f.stem}#{i}", "text": t, "institution": meta.get("institution", "global"),
                                    "network": meta.get("network", ""), "document_type": meta.get("document_type", ""),
                                    "topic": meta.get("topic", ""), "attack_types": meta["attack_types"]})
        self.vecs = self.embed([c["text"] for c in self.chunks])
        self.index = make_index(self.vecs)        # FAISS IndexFlatIP on L2-normalised vectors = cosine similarity
        return self

    def save(self, path=ART / "kb"):
        path.mkdir(exist_ok=True)
        np.save(path / "vectors.npy", self.vecs)
        json.dump(self.chunks, open(path / "chunks.json", "w"))

    @classmethod
    def load(cls, path=ART / "kb", embed_fn=embed):
        kb = cls(embed_fn)
        kb.vecs = np.load(path / "vectors.npy")
        kb.index = make_index(kb.vecs)
        kb.chunks = json.load(open(path / "chunks.json"))
        return kb

    def search(self, query, institution, scope="both", attack=None, k=4, overfetch=200):
        """FAISS has no metadata filter, so over-fetch and filter with the lookup table.
        scope: 'global' | 'institution' (only the flagged institution's own docs) | 'both'."""
        q = self.embed([query])
        scores, ids = self.index.search(q, min(overfetch, len(self.chunks)))
        out = []
        for s, i in zip(scores[0], ids[0]):
            c = self.chunks[i]
            if scope == "global" and c["institution"] != "global": continue
            if scope == "institution" and c["institution"] != institution: continue
            if scope == "both" and c["institution"] not in ("global", institution): continue
            if attack and attack not in c["attack_types"] and "ALL" not in c["attack_types"]: continue
            out.append({**c, "score": float(s)})
            if len(out) == k: break
        return out
