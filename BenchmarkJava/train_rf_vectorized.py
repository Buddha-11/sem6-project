import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

# ── Load vectorized dataset ──────────────────────────────────────────────────
df = pd.read_csv("ml_dataset_vectorized.csv")

print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['label'].value_counts()}\n")

# ── One-hot encode ruleId ────────────────────────────────────────────────────
df = pd.get_dummies(df, columns=["ruleId"])

X = df.drop("label", axis=1)
y = df["label"]

print(f"Feature columns ({len(X.columns)}):")
for c in X.columns:
    print(f"  {c}")

# ── Train / Test split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

print(f"\nTraining samples: {len(X_train)},  Test samples: {len(X_test)}")

# ── Train Random Forest ──────────────────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)
model.fit(X_train, y_train)

# ── Evaluate ─────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)

cm = confusion_matrix(y_test, y_pred)
print("\n=== Confusion Matrix ===")
print(cm)
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=["Non-Vuln (0)", "Vuln (1)"]))

# ── Plot & save confusion matrix ─────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 5))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Non-Vuln (0)", "Vuln (1)"])
disp.plot(ax=ax, cmap="Blues", colorbar=True)
ax.set_title("Random Forest — Confusion Matrix\n(Vectorized Alert Counts)")
plt.tight_layout()
output_img = "confusion_matrix_vectorized.png"
plt.savefig(output_img, dpi=150)
print(f"\nConfusion matrix saved → {output_img}")

# ── Feature Importance (top 20) ───────────────────────────────────────────────
importances = pd.Series(model.feature_importances_, index=X.columns)
top20 = importances.nlargest(20)

fig2, ax2 = plt.subplots(figsize=(10, 6))
top20.sort_values().plot(kind="barh", ax=ax2, color="steelblue")
ax2.set_title("Top-20 Feature Importances (Vectorized RF Model)")
ax2.set_xlabel("Mean Decrease in Impurity")
plt.tight_layout()
plt.savefig("feature_importance_vectorized.png", dpi=150)
print("Feature importance plot saved → feature_importance_vectorized.png")

# ── Save artefacts ────────────────────────────────────────────────────────────
joblib.dump(model, "rf_model_vectorized.pkl")
joblib.dump(X.columns.tolist(), "rf_feature_columns_vectorized.pkl")
print("Model saved → rf_model_vectorized.pkl")
print("Feature columns saved → rf_feature_columns_vectorized.pkl")
