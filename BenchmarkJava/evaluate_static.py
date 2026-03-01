import csv

# Load ground truth
ground_truth = {}
with open("expectedresults-1.2.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        if row[0].startswith("#"):
            continue
        test_id = row[0].strip()
        label = 1 if row[2].strip().lower() == "true" else 0
        ground_truth[test_id] = label

# Load static alerts
static_detected = set()

with open("labeled_static_dataset.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        static_detected.add(row["test_id"])

TP = 0
FP = 0
FN = 0
TN = 0

for test_id, true_label in ground_truth.items():
    predicted = 1 if test_id in static_detected else 0

    if predicted == 1 and true_label == 1:
        TP += 1
    elif predicted == 1 and true_label == 0:
        FP += 1
    elif predicted == 0 and true_label == 1:
        FN += 1
    elif predicted == 0 and true_label == 0:
        TN += 1

# Metrics
precision = TP / (TP + FP) if (TP + FP) > 0 else 0
recall = TP / (TP + FN) if (TP + FN) > 0 else 0
accuracy = (TP + TN) / (TP + FP + FN + TN)
f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print("Confusion Matrix:")
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
