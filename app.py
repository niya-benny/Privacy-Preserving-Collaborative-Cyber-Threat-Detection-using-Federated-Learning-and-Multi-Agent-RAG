"""STEP 10 - deployment demo.  streamlit run app.py
Tabs: Results | Mitigation replay | Incident report (local Llama via Ollama)."""
import json, pickle
import numpy as np, pandas as pd, streamlit as st
from config import ART, OUT, INSTITUTIONS, MITIGATION, WHITELIST
from s6_mitigation import replay

st.set_page_config(page_title="Federated Campus IDS", layout="wide")
st.title("Privacy-preserving collaborative threat detection for educational institutions")
st.caption("Federated XGBoost-style IDS + Secure Aggregation + Multi-Agent RAG (local Llama). Simulation on CICIDS2017.")


@st.cache_resource
def load_model():
    return pickle.load(open(ART / "global_model.pkl", "rb"))


@st.cache_resource
def load_kb():
    from rag.kb import KnowledgeBase
    return KnowledgeBase.load()


@st.cache_data
def load_test():
    d = np.load(ART / "test.npz")
    return {k: d[k] for k in d.files}


tab1, tab2, tab3 = st.tabs(["Results", "Mitigation replay", "Incident report"])

with tab1:
    try:
        st.dataframe(pd.read_csv(OUT / "table_model_comparison.csv", index_col=0).style.format("{:.4f}"), use_container_width=True)
        c1, c2 = st.columns(2)
        c1.image(str(OUT / "fig_per_class_recall.png")); c2.image(str(OUT / "fig_convergence.png"))
        c1.image(str(OUT / "fig_confusion_matrix.png")); c2.image(str(OUT / "partition_heatmap.png"))
        st.text(open(OUT / "secagg_summary.txt").read())
    except FileNotFoundError:
        st.info("Run steps s1 - s5 first.")

with tab2:
    model, te = load_model(), load_test()
    classes = model.classes
    c = st.columns(3)
    thr = c[0].slider("Confidence threshold", 0.5, 0.99, MITIGATION["conf_thr"], 0.01)
    rep = c[1].slider("Detections before block", 1, 10, MITIGATION["repeat"])
    dur = c[2].select_slider("Block duration (s)", [60, 300, 600, 1800, 3600], MITIGATION["duration"])
    if st.button("Replay test traffic"):
        proba = model.predict_proba(te["Xb"]); pred, conf = proba.argmax(1), proba.max(1)
        ts = te["ts"]
        if np.isnan(ts).all(): order, t, d = np.arange(len(pred)), np.arange(len(pred), dtype=float), dur / 60
        else: order, t, d = np.argsort(np.nan_to_num(ts, nan=np.inf), kind="stable"), ts - np.nanmin(ts), dur
        m, inc = replay(order, te["src"], te["inst"], te["y"], pred, conf, t, dict(conf_thr=thr, repeat=rep, duration=d), WHITELIST)
        a, b, c3 = st.columns(3)
        a.metric("Attack flows dropped", f"{m['attack_dropped_pct']:.1f}%"); b.metric("Benign flows wrongly dropped", f"{m['benign_dropped_pct']:.2f}%")
        c3.metric("Wrongly blocked sources", m["wrongly_blocked_sources"])
        df = pd.DataFrame(inc)
        if len(df):
            df["institution"] = [INSTITUTIONS[i] for i in df.pop("institution_id")]; df["predicted_class"] = [classes[i] for i in df["predicted_class"]]
            st.dataframe(df, use_container_width=True)
        st.caption("Replay of labelled flows: no real firewall is touched. Spoofed IPs / shared NAT can cause wrongly blocked hosts in practice.")

with tab3:
    st.write("Select an incident created by the replay (artifacts/incidents.json) or enter an alert manually.")
    try:
        incs = json.load(open(ART / "incidents.json"))
    except FileNotFoundError:
        incs = []
    pick = st.selectbox("Incident", range(len(incs)), format_func=lambda i: f"{incs[i]['institution']} | {incs[i]['predicted_class']} | {incs[i]['src_ip']}") if incs else None
    alert = dict(incs[pick]) if pick is not None else {}
    c = st.columns(4)
    alert["institution"] = c[0].selectbox("Institution", INSTITUTIONS, index=INSTITUTIONS.index(alert["institution"]) if alert else 0)
    alert["predicted_class"] = c[1].selectbox("Attack", [x for x in load_model().classes if x != "BENIGN"], index=0)
    alert["src_ip"] = c[2].text_input("Source IP", alert.get("src_ip", "172.16.0.1"))
    alert["confidence"] = c[3].number_input("Confidence", 0.0, 1.0, float(alert.get("confidence") or 0.95))
    fast = st.checkbox("Fast mode (rule-based attack-analysis agent, fewer LLM calls)", True)
    if st.button("Generate incident report"):
        from rag.agents import Pipeline
        with st.spinner("Local Llama is writing the report (can take 1-3 minutes on CPU)..."):
            try:
                r = Pipeline(load_kb(), load_model().classes, use_llm_for_analysis=not fast).generate(alert)
            except Exception as e:
                st.error(f"Could not reach the local LLM ({e}). Start Ollama and pull the model: `ollama pull llama3:8b`")
                st.stop()
        if r["status"] == "rejected":
            st.error("Alert rejected by input validation: " + ", ".join(r["errors"]))
        else:
            rp = r["report"]
            st.subheader(f"{rp['attack_type']} - {rp['institution']}  ({r['status']})")
            st.write(rp["summary"]); st.markdown(f"**Impact:** {rp['impact']}"); st.markdown("**MITRE:** " + ", ".join(rp["mitre_techniques"]))
            st.markdown("**Response steps (from the institution's own policy):**\n" + "\n".join(f"{i + 1}. {s}" for i, s in enumerate(rp["response_steps"])))
            st.markdown(f"**Escalation:** {rp.get('escalation', '')}")
            with st.expander("Checks, sources and cost"):
                st.json({"checks": r["checks"], "sources": r["sources"], "stats": r["stats"], "dropped_chunks": r["dropped_chunks"]})
