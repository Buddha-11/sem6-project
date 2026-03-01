import csv
import os
from collections import defaultdict

# Load static alerts
alerts = []

with open("labeled_static_dataset.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        alerts.append(row)

# Count alerts per file
alerts_per_file = defaultdict(int)
for row in alerts:
    alerts_per_file[row["test_id"]] += 1

file_lengths = {}
file_contents = {}

# Preload file contents
for row in alerts:
    test_id = row["test_id"]
    file_path = f"src/main/java/org/owasp/benchmark/testcode/{test_id}.java"

    if test_id not in file_contents:
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
                file_contents[test_id] = lines
                file_lengths[test_id] = len(lines)
        except:
            file_contents[test_id] = []
            file_lengths[test_id] = 0

# Dangerous API patterns
dangerous_keywords = [
    "Runtime.getRuntime",
    "exec(",
    "execute(",
    "Statement",
    "PreparedStatement",
    "eval(",
    "FileInputStream",
    "FileOutputStream"
]

# User input indicators
input_keywords = [
    "request.getParameter",
    "getParameter(",
    "Scanner",
    "BufferedReader",
    "readLine(",
    "request.getHeader"
]

ml_rows = []

for row in alerts:
    test_id = row["test_id"]
    line_number = int(row["line"])
    rule = row["ruleId"]
    label = int(row["ground_truth"])

    lines = file_contents[test_id]
    file_len = file_lengths[test_id]
    alert_count = alerts_per_file[test_id]

    density = alert_count / file_len if file_len > 0 else 0

    # --- Code Context Extraction ---
    snippet_start = max(0, line_number - 5)
    snippet_end = min(file_len, line_number + 5)

    snippet = "".join(lines[snippet_start:snippet_end])

    snippet_length = len(snippet)

    # Dangerous API presence
    has_dangerous_api = 0
    for kw in dangerous_keywords:
        if kw in snippet:
            has_dangerous_api = 1
            break

    # User input presence
    has_user_input = 0
    for kw in input_keywords:
        if kw in snippet:
            has_user_input = 1
            break

    ml_rows.append({
        "ruleId": rule,
        "line": line_number,
        "alert_count": alert_count,
        "file_length": file_len,
        "density": density,
        "snippet_length": snippet_length,
        "has_dangerous_api": has_dangerous_api,
        "has_user_input": has_user_input,
        "label": label
    })

with open("ml_dataset_enhanced.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=ml_rows[0].keys())
    writer.writeheader()
    writer.writerows(ml_rows)

print("Enhanced ML dataset built.")
