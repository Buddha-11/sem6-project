import json
import csv
import re

# -------------------------
# Load ground truth
# -------------------------
ground_truth = {}

with open("expectedresults-1.2.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        if row[0].startswith("#"):
            continue
        test_id = row[0].strip()
        label = 1 if row[2].strip().lower() == "true" else 0
        ground_truth[test_id] = label

# -------------------------
# Load LLM results
# -------------------------
with open("llm_results_raw.json") as f:
    llm_results = json.load(f)

# Map test_id → LLM prediction
llm_predictions = {}

for item in llm_results:
    raw = item["llm_raw"]

    # Remove markdown wrapping
    cleaned = raw.replace("```json", "").replace("```", "").strip()

    try:
        parsed = json.loads(cleaned)
        verdict = parsed["verdict"]

        prediction = 1 if verdict == "true_vulnerability" else 0
        llm_predictions[item["test_id"]] = prediction

    except Exception as e:
        print("Parse error:", e)

# -------------------------
# Evaluate
# -------------------------
TP = FP = FN = TN = 0

for test_id, true_label in ground_truth.items():

    # If static never flagged it → LLM never saw it → predicted = 0
    predicted = llm_predictions.get(test_id, 0)

    if predicted == 1 and true_label == 1:
        TP += 1
    elif predicted == 1 and true_label == 0:
        FP += 1
    elif predicted == 0 and true_label == 1:
        FN += 1
    elif predicted == 0 and true_label == 0:
        TN += 1

precision = TP / (TP + FP) if (TP + FP) else 0
recall = TP / (TP + FN) if (TP + FN) else 0
accuracy = (TP + TN) / (TP + FP + FN + TN)
f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0

print("Confusion Matrix (Static + LLM):")
print(f"TP: {TP}")
print(f"FP: {FP}")
print(f"FN: {FN}")
print(f"TN: {TN}")
print()
print("Metrics:")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"Accuracy: {accuracy:.4f}")
print(f"F1 Score: {f1:.4f}")
