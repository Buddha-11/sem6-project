import os
import json
import time
import csv
from google import genai

# Initialize Gemini
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

# Load ground truth (just to know file names exist)
ground_truth = {}
with open("expectedresults-1.2.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        if row[0].startswith("#"):
            continue
        ground_truth[row[0].strip()] = 1 if row[2].strip().lower() == "true" else 0

# Load static findings
static_findings = {}

with open("labeled_static_dataset.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        test_id = row["test_id"]
        rule = row["ruleId"]
        line = row["line"]

        if test_id not in static_findings:
            static_findings[test_id] = []

        static_findings[test_id].append(f"{rule} at line {line}")

# Load sampled files
with open("file_sample.txt") as f:
    sample_files = [line.strip() for line in f.readlines()]

results = []

SLEEP_SECONDS = 15  # avoid quota issue

for i, test_id in enumerate(sample_files):

    file_path = f"src/main/java/org/owasp/benchmark/testcode/{test_id}.java"

    try:
        with open(file_path, "r") as f:
            code = f.read()
    except:
        print(f"Could not read {file_path}")
        continue

    findings = static_findings.get(test_id, [])

    if findings:
        findings_text = "\n".join(findings)
    else:
        findings_text = "No static findings detected."

    prompt = f"""
You are a Java security expert.

Static analysis findings:
{findings_text}

Here is the full Java file:

{code}

Is this file actually vulnerable?

Respond strictly in JSON format:
{{
  "vulnerable": true or false,
  "confidence": 0.0 to 1.0
}}
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={"temperature": 0.0}
        )

        text = response.text

        results.append({
            "test_id": test_id,
            "llm_raw": text
        })

        print(f"Processed {i+1}/20")

        time.sleep(SLEEP_SECONDS)

    except Exception as e:
        print("Error:", e)
        time.sleep(20)

with open("llm_file_level_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("LLM file-level adjudication complete.")
