import json
import csv
import re

# ----------------------------
# Load SARIF alerts
# ----------------------------
with open("results.sarif") as f:
    sarif = json.load(f)

alerts = sarif["runs"][0]["results"]

# ----------------------------
# Load ground truth
# ----------------------------
ground_truth = {}

with open("expectedresults-1.2.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        if row[0].startswith("#"):
            continue
        test_name = row[0].strip()
        is_vulnerable = row[2].strip().lower() == "true"
        ground_truth[test_name] = 1 if is_vulnerable else 0

# ----------------------------
# Match alerts to ground truth
# ----------------------------
labeled_rows = []

for alert in alerts:
    rule = alert["ruleId"]
    file_path = alert["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    line = alert["locations"][0]["physicalLocation"]["region"]["startLine"]

    # Extract BenchmarkTestXXXXX from filename
    match = re.search(r"(BenchmarkTest\d+)", file_path)
    if not match:
        continue

    test_id = match.group(1)

    if test_id in ground_truth:
        label = ground_truth[test_id]
    else:
        label = None  # shouldn't happen

    labeled_rows.append([rule, test_id, file_path, line, label])

# ----------------------------
# Save dataset
# ----------------------------
with open("labeled_static_dataset.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["ruleId", "test_id", "file", "line", "ground_truth"])
    writer.writerows(labeled_rows)

print(f"Labeled {len(labeled_rows)} alerts.")
