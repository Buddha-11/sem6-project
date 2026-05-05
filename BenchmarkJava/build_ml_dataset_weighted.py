"""
build_ml_dataset_weighted.py
----------------------------
Builds upon ml_dataset_vectorized.csv and adds two new derived features:

  same_type_count    — count of alerts of the SAME vulnerability type as
                       the current row's ruleId (i.e. the "self" count).

  weighted_alert_count — a weighted sum of all alert counts, where the
                         alert column matching the current row's ruleId
                         gets a higher weight (SELF_WEIGHT), and all
                         other columns keep weight = 1.0.

  weighted_density   — weighted_alert_count / file_length

The intuition:
  If a row is flagging an XSS vulnerability, having 5 XSS alerts in the
  same file is a much stronger signal than 5 SQL-injection alerts in the
  same file. The self-count should therefore carry more influence.
"""

import pandas as pd
import numpy as np

# Weight applied to the "same type" alert count column
SELF_WEIGHT = 3.0   # tunable — e.g. 2.0, 3.0, 5.0

# ── Rule-ID to dataset column name mapping ────────────────────────────────
# Must match the sanitisation done in build_ml_dataset_vectorized.py
def rule_to_col(rule_id: str) -> str:
    return "alert_count_" + rule_id.replace("/", "__").replace("-", "_")

# ── Load base vectorized dataset ──────────────────────────────────────────
df = pd.read_csv("ml_dataset_vectorized.csv")

# Identify every alert_count_* column
alert_cols = [c for c in df.columns if c.startswith("alert_count_")]

print(f"Alert vector columns: {len(alert_cols)}")
print(f"Dataset shape       : {df.shape}")
print(f"SELF_WEIGHT         : {SELF_WEIGHT}\n")

# ── Derive new features row-by-row ────────────────────────────────────────
same_type_counts      = []
weighted_alert_counts = []
weighted_densities    = []

for _, row in df.iterrows():
    self_col   = rule_to_col(row["ruleId"])
    file_len   = row["file_length"]

    # Count of the SAME vulnerability type
    same_count = row[self_col] if self_col in row.index else 0

    # Weighted sum: boost the self column, everything else weight = 1.0
    w_sum = 0.0
    for col in alert_cols:
        w = SELF_WEIGHT if col == self_col else 1.0
        w_sum += w * row[col]

    w_density = w_sum / file_len if file_len > 0 else 0.0

    same_type_counts.append(same_count)
    weighted_alert_counts.append(w_sum)
    weighted_densities.append(w_density)

df["same_type_count"]      = same_type_counts
df["weighted_alert_count"] = weighted_alert_counts
df["weighted_density"]     = weighted_densities

# ── Replace the original scalar density with weighted_density ─────────────
# Keep original density for reference but place weighted_density right after
col_order = (
    ["file_name", "ruleId", "line"]
    + alert_cols
    + ["same_type_count", "weighted_alert_count",
       "file_length", "density", "weighted_density",
       "snippet_length", "has_dangerous_api", "has_user_input", "label"]
)
df = df[col_order]

output_file = "ml_dataset_weighted.csv"
df.to_csv(output_file, index=False)

print(f"Weighted dataset saved → '{output_file}'")
print(f"Rows: {len(df)} | Columns: {len(df.columns)}")
print(f"\nSample of new columns:")
print(df[["ruleId", "same_type_count", "weighted_alert_count", "density", "weighted_density"]].head(8).to_string(index=False))
