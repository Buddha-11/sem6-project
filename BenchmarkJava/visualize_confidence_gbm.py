"""
visualize_confidence_gbm.py
---------------------------
Generates confidence score analysis for the Gradient Boosting model.
Uses the light theme for visual consistency.
"""

import pandas as pd
import numpy as np
import joblib
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.metrics import accuracy_score

# ── Load model ─────────────────────────────────────────────────────────────
MODEL_PATH = "clf_gradient_boosting.pkl"
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file {MODEL_PATH} not found. Run train_compare_classifiers.py first.")

model = joblib.load(MODEL_PATH)

# ── Load & prepare dataset ─────────────────────────────────────────────────
# GBM in train_compare_classifiers.py uses ml_dataset_weighted.csv
df = pd.read_csv("ml_dataset_weighted.csv")
df = pd.get_dummies(df, columns=["ruleId"])

# Align X and y
X = df.drop("label", axis=1)
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
# Plotting (Light Theme)
# ══════════════════════════════════════════════════════════════════════════════
BINS      = 40
ALPHA     = 0.80
COLOR_V   = "#F72585"   # GBM specific pink from comparison plots
COLOR_NV  = "#457B9D"   # steel blue — non-vulnerabilities
COLOR_THR = "#2ECC71"   # emerald    — threshold line

BG      = "#F8FAFC"
PANEL   = "#FFFFFF"
GRID    = "#E2E8F0"
TEXT    = "#1E293B"
SUBTEXT = "#64748B"

fig = plt.figure(figsize=(18, 5.5))
fig.patch.set_facecolor(BG)
gs  = gridspec.GridSpec(1, 3, figure=fig, wspace=0.35)

def style_ax(ax, title, xlabel, ylabel):
    ax.set_facecolor(PANEL)
    ax.set_title(title, color=TEXT, fontsize=13, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, color=SUBTEXT, fontsize=10)
    ax.set_ylabel(ylabel, color=SUBTEXT, fontsize=10)
    ax.tick_params(colors=SUBTEXT, labelsize=9)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID)
    ax.grid(axis="y", color=GRID, linewidth=0.6, alpha=0.7)
    ax.grid(axis="x", color=GRID, linewidth=0.4, alpha=0.4)

# ── Plot 1 : Vuln confidence distribution ─────────────────────────────────
ax1 = fig.add_subplot(gs[0])
counts1, edges1, patches1 = ax1.hist(
    conf_vuln, bins=BINS, range=(0, 1),
    color=COLOR_V, alpha=ALPHA, edgecolor=COLOR_V, linewidth=0.4
)
for patch, left in zip(patches1, edges1[:-1]):
    patch.set_alpha(ALPHA * (0.4 + 0.6 * left))

ax1.axvline(0.5, color=TEXT, linestyle="--", linewidth=1.2, alpha=0.4, label="Default thresh (0.5)")
ax1.axvline(best_thresh, color=COLOR_THR, linestyle="-.", linewidth=1.4,
            alpha=0.85, label=f"Best thresh ({best_thresh:.2f})")
ax1.legend(fontsize=8, facecolor=PANEL, edgecolor=GRID,
           labelcolor=TEXT, loc="upper left", framealpha=0.8)
style_ax(ax1, "GBM Confidence — True Vulnerabilities", "Confidence Score P(vuln=1)", "Frequency")

# ── Plot 2 : Non-vuln confidence distribution ──────────────────────────────
ax2 = fig.add_subplot(gs[1])
counts2, edges2, patches2 = ax2.hist(
    conf_non_vuln, bins=BINS, range=(0, 1),
    color=COLOR_NV, alpha=ALPHA, edgecolor=COLOR_NV, linewidth=0.4
)
for patch, right in zip(patches2, edges2[1:]):
    patch.set_alpha(ALPHA * (0.4 + 0.6 * (1 - right)))

ax2.axvline(0.5, color=TEXT, linestyle="--", linewidth=1.2, alpha=0.4, label="Default thresh (0.5)")
ax2.axvline(best_thresh, color=COLOR_THR, linestyle="-.", linewidth=1.4,
            alpha=0.85, label=f"Best thresh ({best_thresh:.2f})")
ax2.legend(fontsize=8, facecolor=PANEL, edgecolor=GRID,
           labelcolor=TEXT, loc="upper right", framealpha=0.8)
style_ax(ax2, "GBM Confidence — True Non-Vuln", "Confidence Score P(vuln=1)", "Frequency")

# ── Plot 3 : Accuracy vs Threshold ────────────────────────────────────────
ax3 = fig.add_subplot(gs[2])
ax3.plot(thresholds, accuracies, color=COLOR_V, linewidth=2.2, label="Accuracy")
ax3.fill_between(thresholds, accuracies, alpha=0.15, color=COLOR_V)
ax3.axvline(0.5, color=TEXT, linestyle="--", linewidth=1.2, alpha=0.4, label="Default (0.5)")
ax3.axvline(best_thresh, color=COLOR_THR, linestyle="-.", linewidth=1.6,
            label=f"Best ({best_thresh:.2f}) → {best_acc:.3f}")
ax3.axhline(best_acc, color=COLOR_THR, linestyle=":", linewidth=0.9, alpha=0.5)
ax3.scatter([best_thresh], [best_acc], color=COLOR_THR, s=60, zorder=5)
ax3.set_xlim(0, 1)
ax3.set_ylim(0.4, 1.0)
ax3.legend(fontsize=8, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT, framealpha=0.8)
style_ax(ax3, "Accuracy vs. Decision Threshold (GBM)", "Decision Threshold", "Accuracy")

fig.suptitle("Gradient Boosting Model — Confidence Score Analysis",
             color=TEXT, fontsize=15, fontweight="bold", y=1.01)

output = "visualizations/confidence_analysis_gbm.png"
os.makedirs("visualizations", exist_ok=True)
plt.savefig(output, dpi=160, bbox_inches="tight", facecolor=fig.get_facecolor())
print(f"\nPlot saved → {output}")
plt.close()
