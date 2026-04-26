import os
from groq import Groq
from pathlib import Path

# ===============================
# CONFIG
# ===============================

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise ValueError("Set GROQ_API_KEY using export")

client = Groq(api_key=GROQ_API_KEY)

# ===============================
# HARDCODED TEST ALERTS
# ===============================

alerts = [
    {
        "file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java",
        "line": 57,
        "rule": "java/sql-injection",
        "confidence": 0.73
    }
]

# ===============================
# FILE READER
# ===============================

def get_full_file(file_path):
    try:
        with open(file_path, "r") as f:
            return f.read()
    except:
        return ""

# ===============================
# LLM PATCH GENERATION
# ===============================

def generate_patch_llm(alert):
    code = get_full_file(alert["file"])

    if not code:
        return "No code available"

    prompt = f"""
You are a senior Java security engineer.

Your task is to FIX a security vulnerability in the given Java file.

VULNERABILITY:
{alert["rule"]}

--------------------------------------------------
STRICT SECURITY RULES (MUST FOLLOW):

1. SQL Injection Fix:
   - NEVER allow user input to modify SQL structure
   - NEVER concatenate user input into queries
   - ALWAYS use parameterized queries

2. PreparedStatement vs CallableStatement:
   - Use PreparedStatement for normal queries
   - Use CallableStatement ONLY if calling a FIXED stored procedure
   - NEVER allow user input to control procedure name

3. Stored Procedure Safety:
   - If code uses {{call ...}}, ensure:
     ✔ procedure name is FIXED (hardcoded, not user input)
     ✔ user input is ONLY passed as parameters (e.g., ?)

4. Preserve Logic:
   - DO NOT remove functionality
   - DO NOT hardcode dummy values unless unavoidable
   - Keep original behavior intact

5. Minimal Changes:
   - Modify ONLY the vulnerable lines
   - DO NOT rewrite entire file unnecessarily

6. Output Format:
   - Return ONLY the updated Java code
   - NO explanations
   - NO markdown
   - NO comments like "fixed code below"

--------------------------------------------------

Java File:
{code}
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You fix real-world Java security vulnerabilities correctly."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1  # lower = more deterministic
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"LLM Error: {str(e)}"

# ===============================
# MAIN
# ===============================

if __name__ == "__main__":

    print("\n=== LLM PATCH TEST ===\n")

    for alert in alerts:
        print(f"File: {alert['file']}")
        print(f"Line: {alert['line']}")
        print(f"Rule: {alert['rule']}")
        print(f"Confidence: {alert['confidence']}")

        print("\n--- Generated Patch ---")
        patch = generate_patch_llm(alert)
        print(patch)

        print("-" * 60)