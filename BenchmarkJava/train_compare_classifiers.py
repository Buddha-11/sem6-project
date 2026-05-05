"""
train_compare_classifiers.py
-----------------------------
Trains and compares three classifiers on ml_dataset_weighted.csv:
  1. Random Forest (RF)          — parallel bagging ensemble
  2. Gradient Boosting (GBM)     — sequential boosting ensemble
  3. Support Vector Machine (SVM) — RBF-kernel, margin-based classifier

Saves to visualizations/:
  - confusion_matrices_comparison.png  (3 CMs side by side)
  - roc_curves_comparison.png          (ROC curves on one axes)
  - metrics_comparison.png             (grouped bar chart)
  - pr_curves_comparison.png           (Precision-Recall curves)
"""

import os
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, ConfusionMatrixDisplay,
    roc_curve, auc,
    precision_recall_curve, average_precision_score,
    classification_report
)

# ─────────────────────────────────────────────────────────────────────────────
VIZ_DIR          = "visualizations"
OPTIMIZED_THRESH = 0.414    # applied to RF and GBM
os.makedirs(VIZ_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# 1. Data
# ─────────────────────────────────────────────────────────────────────────────
df = pd.read_csv("ml_dataset_weighted.csv")
df = pd.get_dummies(df, columns=["ruleId"])

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)
print(f"Train: {len(X_train)}  |  Test: {len(X_test)}")
print(f"Class distribution (test):\n{y_test.value_counts().to_string()}\n")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Define classifiers
# ─────────────────────────────────────────────────────────────────────────────
models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    ),
    "Gradient Boosting": GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.08,
        max_depth=4,
        subsample=0.8,
        random_state=42
    ),
    # SVM needs feature scaling → wrap in a Pipeline
    "SVM (RBF)": Pipeline([
        ("scaler", StandardScaler()),
        ("svm", SVC(
            kernel="rbf",
            C=5.0,
            gamma="scale",
            probability=True,       # needed for predict_proba / ROC
            class_weight="balanced",
            random_state=42
        ))
    ])
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. Train, predict, collect metrics
# ─────────────────────────────────────────────────────────────────────────────
results   = {}   # metrics per model
roc_data  = {}   # for ROC curves
pr_data   = {}   # for PR curves
cms        = {}   # confusion matrices

COLORS = {
    "Random Forest"     : "#4CC9F0",
    "Gradient Boosting" : "#F72585",
    "SVM (RBF)"         : "#7BFF7B",
}

for name, clf in models.items():
    print(f"Training {name} ...", end=" ", flush=True)
    clf.fit(X_train, y_train)
    print("done.")

    proba  = clf.predict_proba(X_test)[:, 1]
    thresh = OPTIMIZED_THRESH if name != "SVM (RBF)" else 0.5

    y_pred = (proba >= thresh).astype(int)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    cm   = confusion_matrix(y_test, y_pred)

    fpr, tpr, _ = roc_curve(y_test, proba)
    roc_auc     = auc(fpr, tpr)
    p_curve, r_curve, _ = precision_recall_curve(y_test, proba)
    avg_prec    = average_precision_score(y_test, proba)

    results[name]  = dict(accuracy=acc, precision=prec, recall=rec, f1=f1,
                          roc_auc=roc_auc, avg_precision=avg_prec, threshold=thresh)
    roc_data[name] = (fpr, tpr, roc_auc)
    pr_data[name]  = (r_curve, p_curve, avg_prec)
    cms[name]      = cm

    print(f"  Threshold: {thresh}  |  Acc: {acc:.4f}  |  F1: {f1:.4f}  |  ROC-AUC: {roc_auc:.4f}")
    report = classification_report(y_test, y_pred, target_names=["Non-Vuln", "Vuln"])
    print("\n".join("    " + l for l in report.splitlines()))

# Save models
for name, clf in models.items():
    fname = name.lower().replace(" ", "_").replace("(", "").replace(")", "")
    joblib.dump(clf, f"clf_{fname}.pkl")
    print(f"Saved → clf_{fname}.pkl")

# ─────────────────────────────────────────────────────────────────────────────
# 4. Plots
# ─────────────────────────────────────────────────────────────────────────────
BG      = "#F8FAFC"
PANEL   = "#FFFFFF"
GRID    = "#E2E8F0"
TEXT    = "#1E293B"
SUBTEXT = "#64748B"

def dark_fig(w, h):
    fig = plt.figure(figsize=(w, h))
    fig.patch.set_facecolor(BG)
    return fig

def style(ax, title="", xlabel="", ylabel=""):
    ax.set_facecolor(PANEL)
    if title:   ax.set_title(title,   color=TEXT,    fontsize=11, fontweight="bold", pad=8)
    if xlabel:  ax.set_xlabel(xlabel, color=SUBTEXT, fontsize=9)
    if ylabel:  ax.set_ylabel(ylabel, color=SUBTEXT, fontsize=9)
    ax.tick_params(colors=SUBTEXT, labelsize=8)
    for sp in ax.spines.values(): sp.set_edgecolor(GRID)
    ax.grid(color=GRID, linewidth=0.5, alpha=0.6)

# ── Plot A: Confusion Matrices (3 side-by-side) ────────────────────────────
fig_cm = dark_fig(18, 5.5)
for i, (name, cm) in enumerate(cms.items()):
    ax = fig_cm.add_subplot(1, 3, i+1)
    thresh_label = f"thr={results[name]['threshold']}"
    disp = ConfusionMatrixDisplay(cm, display_labels=["Non-Vuln", "Vuln"])
    disp.plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title(f"{name}\n(Acc={results[name]['accuracy']:.3f}, {thresh_label})",
                 color=TEXT, fontsize=10, fontweight="bold", pad=8)
    ax.set_facecolor(PANEL)
    ax.tick_params(colors=SUBTEXT, labelsize=9)
    ax.xaxis.label.set_color(SUBTEXT)
    ax.yaxis.label.set_color(SUBTEXT)
    for sp in ax.spines.values(): sp.set_edgecolor(GRID)
fig_cm.suptitle("Confusion Matrices — Classifier Comparison",
                color=TEXT, fontsize=14, fontweight="bold", y=1.02)
plt.tight_layout()
p = os.path.join(VIZ_DIR, "confusion_matrices_comparison.png")
plt.savefig(p, dpi=150, bbox_inches="tight", facecolor=BG)
plt.close(); print(f"\nSaved → {p}")

# ── Plot B: ROC Curves ─────────────────────────────────────────────────────
fig_roc = dark_fig(8, 6)
ax_roc  = fig_roc.add_subplot(1,1,1)
ax_roc.plot([0,1],[0,1], color=GRID, linestyle="--", linewidth=1)
for name, (fpr, tpr, roc_auc) in roc_data.items():
    ax_roc.plot(fpr, tpr, color=COLORS[name], linewidth=2.2,
                label=f"{name}  (AUC = {roc_auc:.3f})")
style(ax_roc, "ROC Curves — All Classifiers", "False Positive Rate", "True Positive Rate")
ax_roc.set_xlim(0,1); ax_roc.set_ylim(0,1.02)
ax_roc.fill_between([0,1],[0,1], alpha=0.04, color="white")
ax_roc.legend(facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT, fontsize=9, framealpha=0.8)
plt.tight_layout()
p = os.path.join(VIZ_DIR, "roc_curves_comparison.png")
plt.savefig(p, dpi=150, bbox_inches="tight", facecolor=BG)
plt.close(); print(f"Saved → {p}")

# ── Plot C: Precision-Recall Curves ────────────────────────────────────────
fig_pr = dark_fig(8, 6)
ax_pr  = fig_pr.add_subplot(1,1,1)
baseline = y_test.mean()
ax_pr.axhline(baseline, color=GRID, linestyle="--", linewidth=1,
              label=f"Baseline (AP = {baseline:.3f})")
for name, (r_c, p_c, avg_prec) in pr_data.items():
    ax_pr.plot(r_c, p_c, color=COLORS[name], linewidth=2.2,
               label=f"{name}  (AP = {avg_prec:.3f})")
style(ax_pr, "Precision-Recall Curves — All Classifiers", "Recall", "Precision")
ax_pr.set_xlim(0,1); ax_pr.set_ylim(0,1.02)
ax_pr.legend(facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT, fontsize=9, framealpha=0.8)
plt.tight_layout()
p = os.path.join(VIZ_DIR, "pr_curves_comparison.png")
plt.savefig(p, dpi=150, bbox_inches="tight", facecolor=BG)
plt.close(); print(f"Saved → {p}")

# ── Plot D: Grouped Metrics Bar Chart ──────────────────────────────────────
metrics_list = ["accuracy", "precision", "recall", "f1", "roc_auc"]
metric_labels = ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"]
model_names   = list(results.keys())
x     = np.arange(len(metric_labels))
width = 0.25

fig_bar = dark_fig(13, 6)
ax_bar  = fig_bar.add_subplot(1,1,1)

for i, name in enumerate(model_names):
    vals = [results[name][m] for m in metrics_list]
    bars = ax_bar.bar(x + i*width, vals, width, label=name,
                      color=COLORS[name], alpha=0.85, edgecolor="#1E293B", linewidth=0.5)
    for bar, val in zip(bars, vals):
        ax_bar.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.008,
                    f"{val:.3f}", ha="center", va="bottom",
                    color=TEXT, fontsize=7.5, fontweight="bold")

ax_bar.set_xticks(x + width)
ax_bar.set_xticklabels(metric_labels, color=SUBTEXT, fontsize=10)
ax_bar.set_ylim(0, 1.12)
style(ax_bar, "Classifier Comparison — Key Metrics", "", "Score")
ax_bar.legend(facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT, fontsize=10, framealpha=0.8)
plt.tight_layout()
p = os.path.join(VIZ_DIR, "metrics_comparison.png")
plt.savefig(p, dpi=150, bbox_inches="tight", facecolor=BG)
plt.close(); print(f"Saved → {p}")

# ─────────────────────────────────────────────────────────────────────────────
# 5. Summary table
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*72)
print(f"{'Model':<22} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'AUC':>7} {'Thr':>6}")
print("="*72)
for name, r in results.items():
    print(f"{name:<22} {r['accuracy']:>7.4f} {r['precision']:>7.4f} "
          f"{r['recall']:>7.4f} {r['f1']:>7.4f} {r['roc_auc']:>7.4f} {r['threshold']:>6.3f}")
print("="*72)
print(f"\nAll plots saved to ./{VIZ_DIR}/")
