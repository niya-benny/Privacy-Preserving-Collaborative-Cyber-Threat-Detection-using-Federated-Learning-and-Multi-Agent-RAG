import json
r = json.load(open("outputs/results_baselines.json"))
a, b = r["centralised"]["per_class"], r["xgboost_library_centralised"]["per_class"]
print(f"{'class':14}{'support':>8}{'ours R':>8}{'lib R':>8}{'ours F1':>9}{'lib F1':>8}")
for c in a:
    print(f"{c:14}{a[c]['support']:>8}{a[c]['recall']:>8.3f}{b[c]['recall']:>8.3f}{a[c]['f1']:>9.3f}{b[c]['f1']:>8.3f}")