import json
import csv

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
# Load static detections
# -------------------------
static_detected = set()

with open("labeled_static_dataset.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        static_detected.add(row["test_id"])

# -------------------------
# Load LLM results
# -------------------------
with open("llm_results_raw.json") as f:
    llm_results = json.load(f)

llm_predictions = {}
subset_ids = set()

for item in llm_results:
    test_id = item["test_id"]
    subset_ids.add(test_id)

    raw = item["llm_raw"]
    cleaned = raw.replace("```json", "").replace("```", "").strip()

    parsed = json.loads(cleaned)
    verdict = parsed["verdict"]

    prediction = 1 if verdict == "true_vulnerability" else 0
    llm_predictions[test_id] = prediction

# -------------------------
# Evaluate ONLY subset
# -------------------------

print(f"Evaluating on {len(subset_ids)} files\n")

# ---- Static metrics on subset ----
TP_s = FP_s = FN_s = TN_s = 0

for test_id in subset_ids:
    true_label = ground_truth[test_id]
    predicted = 1 if test_id in static_detected else 0

    if predicted == 1 and true_label == 1:
        TP_s += 1
    elif predicted == 1 and true_label == 0:
        FP_s += 1
    elif predicted == 0 and true_label == 1:
        FN_s += 1
    elif predicted == 0 and true_label == 0:
        TN_s += 1

precision_s = TP_s / (TP_s + FP_s) if (TP_s + FP_s) else 0
recall_s = TP_s / (TP_s + FN_s) if (TP_s + FN_s) else 0
f1_s = (2 * precision_s * recall_s) / (precision_s + recall_s) if (precision_s + recall_s) else 0

# ---- Static + LLM metrics on subset ----
TP_l = FP_l = FN_l = TN_l = 0

for test_id in subset_ids:
    true_label = ground_truth[test_id]
    predicted = llm_predictions[test_id]

    if predicted == 1 and true_label == 1:
        TP_l += 1
    elif predicted == 1 and true_label == 0:
        FP_l += 1
    elif predicted == 0 and true_label == 1:
        FN_l += 1
    elif predicted == 0 and true_label == 0:
        TN_l += 1

precision_l = TP_l / (TP_l + FP_l) if (TP_l + FP_l) else 0
recall_l = TP_l / (TP_l + FN_l) if (TP_l + FN_l) else 0
f1_l = (2 * precision_l * recall_l) / (precision_l + recall_l) if (precision_l + recall_l) else 0

# -------------------------
# Print Results
# -------------------------

print("STATIC (subset):")
print(f"TP: {TP_s}, FP: {FP_s}, FN: {FN_s}, TN: {TN_s}")
print(f"Precision: {precision_s:.4f}")
print(f"Recall: {recall_s:.4f}")
print(f"F1 Score: {f1_s:.4f}\n")

print("STATIC + LLM (subset):")
print(f"TP: {TP_l}, FP: {FP_l}, FN: {FN_l}, TN: {TN_l}")
print(f"Precision: {precision_l:.4f}")
print(f"Recall: {recall_l:.4f}")
print(f"F1 Score: {f1_l:.4f}")
