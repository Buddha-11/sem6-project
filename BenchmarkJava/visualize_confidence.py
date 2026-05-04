"""
visualize_confidence.py
-----------------------
Generates three plots for the vectorized Random Forest model:
  1. Confidence score distribution for actual vulnerabilities  (label = 1)
  2. Confidence score distribution for actual non-vulnerabilities (label = 0)
  3. Accuracy vs. decision threshold (to guide threshold selection)
"""

import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.metrics import accuracy_score

# ── Load model & feature list ──────────────────────────────────────────────
model   = joblib.load("rf_model_vectorized.pkl")
feat_cols = joblib.load("rf_feature_columns_vectorized.pkl")

# ── Load & prepare dataset ─────────────────────────────────────────────────
df = pd.read_csv("ml_dataset_vectorized.csv")
df = pd.get_dummies(df, columns=["ruleId"])

# Align columns exactly as during training (fill any missing OHE cols with 0)
for col in feat_cols:
    if col not in df.columns:
        df[col] = 0
df = df[feat_cols + ["label"]]

X = df[feat_cols]
y = df["label"].values

# ── Predict probabilities (confidence = P(vuln=1)) ─────────────────────────
proba = model.predict_proba(X)[:, 1]   # P(class = 1)

conf_vuln     = proba[y == 1]   # confidence scores for true vulnerabilities
conf_non_vuln = proba[y == 0]   # confidence scores for true non-vulnerabilities

print(f"Total samples   : {len(y)}")
print(f"  Vuln  (label=1): {(y==1).sum()}")
print(f"  Non-v (label=0): {(y==0).sum()}")
print(f"Mean confidence (vuln)    : {conf_vuln.mean():.4f}")
print(f"Mean confidence (non-vuln): {conf_non_vuln.mean():.4f}")

# ── Accuracy vs Threshold ──────────────────────────────────────────────────
thresholds  = np.linspace(0.01, 0.99, 200)
accuracies  = [accuracy_score(y, (proba >= t).astype(int)) for t in thresholds]
best_idx    = int(np.argmax(accuracies))
best_thresh = thresholds[best_idx]
best_acc    = accuracies[best_idx]
print(f"\nBest threshold  : {best_thresh:.3f}  →  Accuracy = {best_acc:.4f}")

# ══════════════════════════════════════════════════════════════════════════════
# Plotting
# ══════════════════════════════════════════════════════════════════════════════
BINS      = 40
ALPHA     = 0.80
COLOR_V   = "#E63946"   # vivid red  — vulnerabilities
COLOR_NV  = "#457B9D"   # steel blue — non-vulnerabilities
COLOR_THR = "#2ECC71"   # emerald    — threshold line

fig = plt.figure(figsize=(18, 5.5))
fig.patch.set_facecolor("#0F172A")
gs  = gridspec.GridSpec(1, 3, figure=fig, wspace=0.35)

# ── shared style helper ────────────────────────────────────────────────────
def style_ax(ax, title, xlabel, ylabel):
    ax.set_facecolor("#1E293B")
    ax.set_title(title, color="white", fontsize=13, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, color="#CBD5E1", fontsize=10)
    ax.set_ylabel(ylabel, color="#CBD5E1", fontsize=10)
    ax.tick_params(colors="#94A3B8", labelsize=9)
    for spine in ax.spines.values():
        spine.set_edgecolor("#334155")
    ax.grid(axis="y", color="#334155", linewidth=0.6, alpha=0.7)
    ax.grid(axis="x", color="#334155", linewidth=0.4, alpha=0.4)

# ── Plot 1 : Vuln confidence distribution ─────────────────────────────────
ax1 = fig.add_subplot(gs[0])
counts1, edges1, patches1 = ax1.hist(
    conf_vuln, bins=BINS, range=(0, 1),
    color=COLOR_V, alpha=ALPHA, edgecolor="#FF6B6B", linewidth=0.4
)
# gradient-ish fill — darken low-confidence bins
for patch, left in zip(patches1, edges1[:-1]):
    patch.set_alpha(ALPHA * (0.4 + 0.6 * left))   # bins near 1 are brighter

ax1.axvline(0.5, color="white", linestyle="--", linewidth=1.2, alpha=0.6, label="Default thresh (0.5)")
ax1.axvline(best_thresh, color=COLOR_THR, linestyle="-.", linewidth=1.4,
            alpha=0.85, label=f"Best thresh ({best_thresh:.2f})")
ax1.legend(fontsize=8, facecolor="#1E293B", edgecolor="#475569",
           labelcolor="white", loc="upper left")
style_ax(ax1,
         "Confidence Score — True Vulnerabilities",
         "Confidence Score  P(vuln=1)",
         "Frequency")

# ── Plot 2 : Non-vuln confidence distribution ──────────────────────────────
ax2 = fig.add_subplot(gs[1])
counts2, edges2, patches2 = ax2.hist(
    conf_non_vuln, bins=BINS, range=(0, 1),
    color=COLOR_NV, alpha=ALPHA, edgecolor="#74B3CE", linewidth=0.4
)
for patch, right in zip(patches2, edges2[1:]):
    patch.set_alpha(ALPHA * (0.4 + 0.6 * (1 - right)))  # bins near 0 are brighter

ax2.axvline(0.5, color="white", linestyle="--", linewidth=1.2, alpha=0.6, label="Default thresh (0.5)")
ax2.axvline(best_thresh, color=COLOR_THR, linestyle="-.", linewidth=1.4,
            alpha=0.85, label=f"Best thresh ({best_thresh:.2f})")
ax2.legend(fontsize=8, facecolor="#1E293B", edgecolor="#475569",
           labelcolor="white", loc="upper right")
style_ax(ax2,
         "Confidence Score — True Non-Vulnerabilities",
         "Confidence Score  P(vuln=1)",
         "Frequency")

# ── Plot 3 : Accuracy vs Threshold ────────────────────────────────────────
ax3 = fig.add_subplot(gs[2])
ax3.plot(thresholds, accuracies, color="#A78BFA", linewidth=2.2, label="Accuracy")
ax3.fill_between(thresholds, accuracies, alpha=0.15, color="#A78BFA")
ax3.axvline(0.5, color="white", linestyle="--", linewidth=1.2, alpha=0.6, label="Default (0.5)")
ax3.axvline(best_thresh, color=COLOR_THR, linestyle="-.", linewidth=1.6,
            label=f"Best ({best_thresh:.2f}) → {best_acc:.3f}")
ax3.axhline(best_acc, color=COLOR_THR, linestyle=":", linewidth=0.9, alpha=0.5)
ax3.scatter([best_thresh], [best_acc], color=COLOR_THR, s=60, zorder=5)
ax3.set_xlim(0, 1)
ax3.set_ylim(0.4, 1.0)
ax3.legend(fontsize=8, facecolor="#1E293B", edgecolor="#475569", labelcolor="white")
style_ax(ax3,
         "Accuracy vs. Decision Threshold",
         "Decision Threshold",
         "Accuracy")

# ── Master title ───────────────────────────────────────────────────────────
fig.suptitle(
    "Vectorized RF Model — Confidence Score Analysis",
    color="white", fontsize=15, fontweight="bold", y=1.01
)

output = "confidence_analysis.png"
plt.savefig(output, dpi=160, bbox_inches="tight",
            facecolor=fig.get_facecolor())
print(f"\nPlot saved → {output}")
plt.close()
