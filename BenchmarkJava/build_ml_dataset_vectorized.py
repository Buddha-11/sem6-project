import csv
import os
from collections import defaultdict

# Load static alerts
alerts = []

with open("labeled_static_dataset.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        alerts.append(row)

# ---- Determine all unique ruleIds (sorted for determinism) ----
all_rule_ids = sorted(set(row["ruleId"] for row in alerts))
print(f"Found {len(all_rule_ids)} unique vulnerability types:")
for r in all_rule_ids:
    print(f"  - {r}")

# ---- Count per-rule alerts per file ----
# alerts_per_file_rule[test_id][ruleId] = count
alerts_per_file_rule = defaultdict(lambda: defaultdict(int))
for row in alerts:
    alerts_per_file_rule[row["test_id"]][row["ruleId"]] += 1

# Total alert count per file (sum across all rules)
alerts_per_file_total = {
    test_id: sum(rule_counts.values())
    for test_id, rule_counts in alerts_per_file_rule.items()
}

# ---- Preload file contents ----
file_lengths = {}
file_contents = {}

for row in alerts:
    test_id = row["test_id"]
    file_path = f"src/main/java/org/owasp/benchmark/testcode/{test_id}.java"
    if test_id not in file_contents:
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
                file_contents[test_id] = lines
                file_lengths[test_id] = len(lines)
        except Exception:
            file_contents[test_id] = []
            file_lengths[test_id] = 0

# ---- Dangerous API patterns ----
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

# ---- User input indicators ----
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

    # --- Vectorized alert counts per rule ---
    rule_counts = alerts_per_file_rule[test_id]
    # Use sanitized column name: replace / and - with _
    alert_vector = {
        f"alert_count_{r.replace('/', '__').replace('-', '_')}": rule_counts.get(r, 0)
        for r in all_rule_ids
    }

    # --- Total count (sum of vector) for density ---
    total_alerts = alerts_per_file_total[test_id]
    density = total_alerts / file_len if file_len > 0 else 0

    # --- Code Context Extraction ---
    snippet_start = max(0, line_number - 5)
    snippet_end = min(file_len, line_number + 5)
    snippet = "".join(lines[snippet_start:snippet_end])
    snippet_length = len(snippet)

    # Dangerous API presence
    has_dangerous_api = int(any(kw in snippet for kw in dangerous_keywords))

    # User input presence
    has_user_input = int(any(kw in snippet for kw in input_keywords))

    record = {
        "file_name": test_id,
        "ruleId": rule,
        "line": line_number,
        **alert_vector,           # 13 per-rule count columns
        "file_length": file_len,
        "density": density,       # updated: total_alerts / file_length
        "snippet_length": snippet_length,
        "has_dangerous_api": has_dangerous_api,
        "has_user_input": has_user_input,
        "label": label,
    }
    ml_rows.append(record)

output_file = "ml_dataset_vectorized.csv"
with open(output_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=ml_rows[0].keys())
    writer.writeheader()
    writer.writerows(ml_rows)

print(f"\nVectorized ML dataset written to '{output_file}' ({len(ml_rows)} rows).")
print(f"New alert-count columns ({len(all_rule_ids)}):")
for r in all_rule_ids:
    col = f"alert_count_{r.replace('/', '__').replace('-', '_')}"
    print(f"  {col}")
