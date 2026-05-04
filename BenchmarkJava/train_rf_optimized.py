import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay, accuracy_score

# ── Load vectorized dataset ──────────────────────────────────────────────────
df = pd.read_csv("ml_dataset_vectorized.csv")

# ── One-hot encode ruleId ────────────────────────────────────────────────────
df = pd.get_dummies(df, columns=["ruleId"])

# Define target and features
X = df.drop("label", axis=1)
y = df["label"]

# ── Train / Test split ───────────────────────────────────────────────────────
# Using same random_state as before for direct comparison
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# ── Train Random Forest ──────────────────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)
model.fit(X_train, y_train)

# ── Prediction with Optimized Threshold ──────────────────────────────────────
OPTIMIZED_THRESHOLD = 0.414

# Get probabilities for the positive class (Vuln)
y_probs = model.predict_proba(X_test)[:, 1]

# Apply the custom threshold
y_pred_optimized = (y_probs >= OPTIMIZED_THRESHOLD).astype(int)

# Default predictions for comparison
y_pred_default = model.predict(X_test)

# ── Evaluation ─────────────────────────────────────────────────────────────────
acc_default = accuracy_score(y_test, y_pred_default)
acc_optimized = accuracy_score(y_test, y_pred_optimized)

print(f"=== Threshold Comparison ===")
print(f"Default Threshold (0.500) Accuracy: {acc_default:.4f}")
print(f"Optimized Threshold ({OPTIMIZED_THRESHOLD:.3f}) Accuracy: {acc_optimized:.4f}")
print(f"Improvement: {((acc_optimized - acc_default) * 100):.2f}%\n")

cm = confusion_matrix(y_test, y_pred_optimized)
print("=== Confusion Matrix (Optimized) ===")
print(cm)

print("\n=== Classification Report (Optimized) ===")
print(classification_report(y_test, y_pred_optimized, target_names=["Non-Vuln (0)", "Vuln (1)"]))

# ── Plot & save confusion matrix ─────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 5))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Non-Vuln (0)", "Vuln (1)"])
disp.plot(ax=ax, cmap="Greens", colorbar=True)
ax.set_title(f"Optimized Random Forest (Threshold: {OPTIMIZED_THRESHOLD})\nConfusion Matrix")
plt.tight_layout()
output_img = "confusion_matrix_optimized.png"
plt.savefig(output_img, dpi=150)
print(f"\nConfusion matrix saved → {output_img}")

# ── Save optimized model metadata ─────────────────────────────────────────────
joblib.dump(model, "rf_model_optimized.pkl")
joblib.dump(X.columns.tolist(), "rf_feature_columns_optimized.pkl")
# Also save the threshold so the pipeline knows what to use
joblib.dump({"threshold": OPTIMIZED_THRESHOLD}, "rf_threshold_metadata.pkl")

print("Optimized model and threshold metadata saved.")
