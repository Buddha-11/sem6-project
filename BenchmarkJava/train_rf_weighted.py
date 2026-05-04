"""
train_rf_weighted.py
--------------------
Trains a Random Forest on ml_dataset_weighted.csv (which adds
same_type_count, weighted_alert_count, and weighted_density to the
vectorized feature set).

Evaluates with both the default (0.5) and optimised (0.414) thresholds.
Produces and saves into visualizations/:
  1. confusion_matrix_weighted.png
  2. feature_importance_weighted.png
  3. confidence_analysis_weighted.png  (3-panel confidence / threshold plot)
"""

import os
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    ConfusionMatrixDisplay, accuracy_score
)

VIZ_DIR           = "visualizations"
OPTIMIZED_THRESH  = 0.414
os.makedirs(VIZ_DIR, exist_ok=True)

# ── Load dataset ─────────────────────────────────────────────────────────────
df = pd.read_csv("ml_dataset_weighted.csv")
print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['label'].value_counts()}\n")

# ── One-hot encode ruleId ─────────────────────────────────────────────────────
df = pd.get_dummies(df, columns=["ruleId"])

X = df.drop("label", axis=1)
y = df["label"]

print(f"Total features: {len(X.columns)}")
print("New features added over vectorized model:")
for c in ["same_type_count", "weighted_alert_count", "weighted_density"]:
    print(f"  ✓ {c}")

# ── Train / Test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)
print(f"\nTraining samples: {len(X_train)}  |  Test samples: {len(X_test)}")

# ── Train Random Forest ───────────────────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)
model.fit(X_train, y_train)

# ── Probabilities ─────────────────────────────────────────────────────────────
y_probs           = model.predict_proba(X_test)[:, 1]
y_pred_default    = model.predict(X_test)                        # threshold 0.5
y_pred_optimized  = (y_probs >= OPTIMIZED_THRESH).astype(int)   # threshold 0.414

acc_default   = accuracy_score(y_test, y_pred_default)
acc_optimized = accuracy_score(y_test, y_pred_optimized)

print(f"\n=== Threshold Comparison (Weighted Model) ===")
print(f"Default  (0.500) Accuracy : {acc_default:.4f}")
print(f"Optimized ({OPTIMIZED_THRESH}) Accuracy : {acc_optimized:.4f}")
print(f"Improvement over default  : {((acc_optimized - acc_default)*100):.2f}%")

cm = confusion_matrix(y_test, y_pred_optimized)
print(f"\n=== Confusion Matrix (threshold = {OPTIMIZED_THRESH}) ===")
print(cm)
print(f"\n=== Classification Report (threshold = {OPTIMIZED_THRESH}) ===")
print(classification_report(y_test, y_pred_optimized,
                            target_names=["Non-Vuln (0)", "Vuln (1)"]))

# ═════════════════════════════════════════════════════════════════════════════
# Plot 1 — Confusion Matrix
# ═════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(7, 5))
disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                              display_labels=["Non-Vuln (0)", "Vuln (1)"])
disp.plot(ax=ax, cmap="Purples", colorbar=True)
ax.set_title(f"Weighted RF — Confusion Matrix\n(threshold = {OPTIMIZED_THRESH})")
plt.tight_layout()
p = os.path.join(VIZ_DIR, "confusion_matrix_weighted.png")
plt.savefig(p, dpi=150)
plt.close()
print(f"\nSaved → {p}")

# ═════════════════════════════════════════════════════════════════════════════
# Plot 2 — Feature Importance (top 20)
# ═════════════════════════════════════════════════════════════════════════════
importances = pd.Series(model.feature_importances_, index=X.columns)
top20 = importances.nlargest(20).sort_values()

fig2, ax2 = plt.subplots(figsize=(11, 6))
colors = ["#9B5DE5" if c in ["same_type_count","weighted_alert_count","weighted_density"]
          else "#4CC9F0" for c in top20.index]
top20.plot(kind="barh", ax=ax2, color=colors)
ax2.set_title("Top-20 Feature Importances — Weighted RF Model\n"
              "(purple = new weighted features)")
ax2.set_xlabel("Mean Decrease in Impurity")
plt.tight_layout()
p = os.path.join(VIZ_DIR, "feature_importance_weighted.png")
plt.savefig(p, dpi=150)
plt.close()
print(f"Saved → {p}")

# ═════════════════════════════════════════════════════════════════════════════
# Plot 3 — 3-panel Confidence Analysis
# ═════════════════════════════════════════════════════════════════════════════
# Run on the FULL dataset (not just test) for richer distributions
X_all    = df.drop("label", axis=1)
y_all    = df["label"].values
proba_all = model.predict_proba(X_all)[:, 1]

conf_vuln     = proba_all[y_all == 1]
conf_non_vuln = proba_all[y_all == 0]

thresholds  = np.linspace(0.01, 0.99, 200)
accuracies  = [accuracy_score(y_all, (proba_all >= t).astype(int)) for t in thresholds]
best_idx    = int(np.argmax(accuracies))
best_thresh = thresholds[best_idx]
best_acc    = accuracies[best_idx]
print(f"\nBest threshold (weighted model): {best_thresh:.3f}  →  Accuracy = {best_acc:.4f}")

BINS     = 40
ALPHA    = 0.80
C_V      = "#E63946"
C_NV     = "#457B9D"
C_THR    = "#2ECC71"

fig3 = plt.figure(figsize=(18, 5.5))
fig3.patch.set_facecolor("#0F172A")
gs = gridspec.GridSpec(1, 3, figure=fig3, wspace=0.35)

def style_ax(ax, title, xlabel, ylabel):
    ax.set_facecolor("#1E293B")
    ax.set_title(title, color="white", fontsize=12, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, color="#CBD5E1", fontsize=9)
    ax.set_ylabel(ylabel, color="#CBD5E1", fontsize=9)
    ax.tick_params(colors="#94A3B8", labelsize=8)
    for sp in ax.spines.values():
        sp.set_edgecolor("#334155")
    ax.grid(axis="y", color="#334155", linewidth=0.6, alpha=0.7)
    ax.grid(axis="x", color="#334155", linewidth=0.4, alpha=0.4)

# Panel A — Vuln distribution
ax1 = fig3.add_subplot(gs[0])
counts1, edges1, patches1 = ax1.hist(conf_vuln, bins=BINS, range=(0,1),
                                      color=C_V, alpha=ALPHA, edgecolor="#FF6B6B", linewidth=0.4)
for patch, left in zip(patches1, edges1[:-1]):
    patch.set_alpha(ALPHA * (0.4 + 0.6 * left))
ax1.axvline(0.5,         color="white", linestyle="--", lw=1.2, alpha=0.6, label="Default (0.5)")
ax1.axvline(best_thresh, color=C_THR,   linestyle="-.", lw=1.4, label=f"Best ({best_thresh:.2f})")
ax1.legend(fontsize=8, facecolor="#1E293B", edgecolor="#475569", labelcolor="white", loc="upper left")
style_ax(ax1, "Confidence — True Vulnerabilities", "P(vuln=1)", "Frequency")

# Panel B — Non-vuln distribution
ax2 = fig3.add_subplot(gs[1])
counts2, edges2, patches2 = ax2.hist(conf_non_vuln, bins=BINS, range=(0,1),
                                      color=C_NV, alpha=ALPHA, edgecolor="#74B3CE", linewidth=0.4)
for patch, right in zip(patches2, edges2[1:]):
    patch.set_alpha(ALPHA * (0.4 + 0.6*(1-right)))
ax2.axvline(0.5,         color="white", linestyle="--", lw=1.2, alpha=0.6, label="Default (0.5)")
ax2.axvline(best_thresh, color=C_THR,   linestyle="-.", lw=1.4, label=f"Best ({best_thresh:.2f})")
ax2.legend(fontsize=8, facecolor="#1E293B", edgecolor="#475569", labelcolor="white", loc="upper right")
style_ax(ax2, "Confidence — True Non-Vulnerabilities", "P(vuln=1)", "Frequency")

# Panel C — Accuracy vs Threshold
ax3 = fig3.add_subplot(gs[2])
ax3.plot(thresholds, accuracies, color="#A78BFA", linewidth=2.2, label="Accuracy")
ax3.fill_between(thresholds, accuracies, alpha=0.15, color="#A78BFA")
ax3.axvline(0.5,         color="white", linestyle="--", lw=1.2, alpha=0.6, label="Default (0.5)")
ax3.axvline(best_thresh, color=C_THR,   linestyle="-.", lw=1.6,
            label=f"Best ({best_thresh:.2f}) → {best_acc:.3f}")
ax3.axhline(best_acc,   color=C_THR, linestyle=":", lw=0.9, alpha=0.5)
ax3.scatter([best_thresh], [best_acc], color=C_THR, s=60, zorder=5)
ax3.set_xlim(0, 1); ax3.set_ylim(0.4, 1.0)
ax3.legend(fontsize=8, facecolor="#1E293B", edgecolor="#475569", labelcolor="white")
style_ax(ax3, "Accuracy vs. Decision Threshold", "Threshold", "Accuracy")

fig3.suptitle("Weighted RF Model — Confidence Score Analysis",
              color="white", fontsize=14, fontweight="bold", y=1.01)

p = os.path.join(VIZ_DIR, "confidence_analysis_weighted.png")
plt.savefig(p, dpi=160, bbox_inches="tight", facecolor=fig3.get_facecolor())
plt.close()
print(f"Saved → {p}")

# ── Save artefacts ──────────────────────────────────────────────────────────
joblib.dump(model, "rf_model_weighted.pkl")
joblib.dump(X.columns.tolist(), "rf_feature_columns_weighted.pkl")
joblib.dump({"threshold": OPTIMIZED_THRESH}, "rf_threshold_weighted.pkl")
print("\nModel artefacts saved.")
print(f"\nAll visualizations → ./{VIZ_DIR}/")
