import json
import csv

with open("results.sarif") as f:
    data = json.load(f)

alerts = data["runs"][0]["results"]

rows = []

for alert in alerts:
    rule = alert["ruleId"]
    file = alert["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    line = alert["locations"][0]["physicalLocation"]["region"]["startLine"]
    message = alert["message"]["text"]

    rows.append([rule, file, line, message])

with open("alerts.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["ruleId", "file", "line", "message"])
    writer.writerows(rows)

print(f"Extracted {len(rows)} alerts.")
