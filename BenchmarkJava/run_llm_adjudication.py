import json
import os
import time
from google import genai

# Initialize Gemini client
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

# Load prepared inputs
with open("llm_inputs.json") as f:
    inputs = json.load(f)

results = []

MAX_ALERTS = 10  # start small
SLEEP_SECONDS= 15
for i, item in enumerate(inputs[:MAX_ALERTS]):

    prompt = f"""
You are a Java security expert.

The following code was flagged by static analysis for rule:
{item['rule']}

Determine:
1. Is this a TRUE vulnerability?
2. Or is it a FALSE positive?

Respond strictly in JSON format:
{{
  "verdict": "true_vulnerability" or "false_positive",
  "confidence": 0.0 to 1.0
}}

Code:
{item['snippet']}
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={
                "temperature": 0.0
            }
        )

        text = response.text

        results.append({
            "test_id": item["test_id"],
            "rule": item["rule"],
            "llm_raw": text
        })

        print(f"Processed {i+1}")

        time.sleep(SLEEP_SECONDS)

    except Exception as e:
        print("Error:", e)

with open("llm_results_raw.json", "w") as f:
    json.dump(results, f, indent=2)

print("LLM adjudication complete.")
