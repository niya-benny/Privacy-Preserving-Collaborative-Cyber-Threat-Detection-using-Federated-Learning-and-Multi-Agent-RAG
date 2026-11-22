|                               |   Accuracy |   Precision (macro) |   Recall (macro) |   F1 (macro) |    FAR |    AMR |
|:------------------------------|-----------:|--------------------:|-----------------:|-------------:|-------:|-------:|
| Local only - Institution_A    |     0.9898 |              0.8473 |           0.7768 |       0.8044 | 0.0024 | 0.0168 |
| Local only - Institution_B    |     0.9895 |              0.9644 |           0.7787 |       0.8016 | 0.0028 | 0.017  |
| Local only - Institution_C    |     0.9849 |              0.7442 |           0.5857 |       0.6113 | 0.005  | 0.0238 |
| Local only - Institution_D    |     0.9902 |              0.8206 |           0.7726 |       0.7776 | 0.0062 | 0.0125 |
| Local only - Institution_E    |     0.9876 |              0.6973 |           0.6684 |       0.6684 | 0.0057 | 0.0178 |
| Centralised (pooled data)     |     0.9913 |              0.9168 |           0.9042 |       0.8988 | 0.0074 | 0.0095 |
| XGBoost library (centralised) |     0.9876 |              0.8686 |           0.848  |       0.839  | 0.0117 | 0.0121 |
| Federated + SecAgg (ours)     |     0.9913 |              0.9168 |           0.9042 |       0.8988 | 0.0074 | 0.0095 |