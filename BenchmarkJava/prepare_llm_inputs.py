import json
import re

CONTEXT = 12  # smaller context first for cost control

# Load SARIF
with open("results.sarif") as f:
    sarif = json.load(f)

alerts = sarif["runs"][0]["results"]

llm_inputs = []

for alert in alerts:
    rule = alert["ruleId"]
    file_path = alert["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    line = alert["locations"][0]["physicalLocation"]["region"]["startLine"]

    # Extract test ID
    match = re.search(r"(BenchmarkTest\d+)", file_path)
    if not match:
        continue
    test_id = match.group(1)

    # Read file
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
    except:
        continue

    start = max(0, line - CONTEXT - 1)
    end = min(len(lines), line + CONTEXT)
    snippet = "".join(lines[start:end])

    llm_inputs.append({
        "test_id": test_id,
        "rule": rule,
        "file": file_path,
        "line": line,
        "snippet": snippet
    })

with open("llm_inputs.json", "w") as f:
    json.dump(llm_inputs, f, indent=2)

print(f"Prepared {len(llm_inputs)} LLM inputs.")
