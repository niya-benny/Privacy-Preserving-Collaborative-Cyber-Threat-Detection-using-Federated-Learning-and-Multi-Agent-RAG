#!/usr/bin/env bash
# Full pipeline. Dry run on fake data first:  python make_synthetic.py && bash run_all.sh   (then delete data/raw/synthetic_* and artifacts/)
set -e
python s1_preprocess.py
python s2_partition.py
python s3_train_baselines.py
python s4_train_federated.py --compare-plain
python s4_train_federated.py --poison 0.3          # data-poisoning experiment (saved separately, does not overwrite the model)
python s5_evaluate.py
python s6_mitigation.py
python s7_build_kb.py
python s8_generate_reports.py --n 12 --fast        # needs Ollama running
python s9_eval_rag.py
echo "All done. Launch the demo with:  streamlit run app.py"
