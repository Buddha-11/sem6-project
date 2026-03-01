import csv

# Load ground truth
ground_truth = {}
with open("expectedresults-1.2.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        if row[0].startswith("#"):
            continue
        ground_truth[row[0].strip()] = 1 if row[2].strip().lower() == "true" else 0

# Load static detections
static_detected = set()
with open("labeled_static_dataset.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        static_detected.add(row["test_id"])

# Load sample
with open("file_sample.txt") as f:
    sample_files = [line.strip() for line in f.readlines()]

TP = FP = FN = TN = 0

for test_id in sample_files:
    true_label = ground_truth[test_id]
    predicted = 1 if test_id in static_detected else 0

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
f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0
accuracy = (TP + TN) / 20

print("STATIC (File-Level on 20 files)")
print(f"TP: {TP}, FP: {FP}, FN: {FN}, TN: {TN}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1: {f1:.4f}")
print(f"Accuracy: {accuracy:.4f}")
