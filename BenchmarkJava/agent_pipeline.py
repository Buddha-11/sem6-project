import os
import subprocess
import json
import joblib
import pandas as pd
from pathlib import Path

# ===============================
# CONFIG
# ===============================

DB_NAME = "benchmark-db"
SARIF_FILE = "agent_results.sarif"
MODEL_FILE = "rf_model.pkl"

JAVA_SOURCE_ROOT = "src/main/java"


# ===============================
# STEP 1 — Detect Changed Files
# ===============================

def get_changed_java_files():
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        files = result.stdout.strip().split("\n")
        java_files = [f for f in files if f.endswith(".java")]
        return java_files
    except Exception:
        return []


# ===============================
# STEP 2 — Rebuild CodeQL DB
# ===============================

def rebuild_codeql_database():
    if os.path.exists(DB_NAME):
        subprocess.run(["rm", "-rf", DB_NAME])

    print("Rebuilding CodeQL database...")

    subprocess.run([
        "codeql", "database", "create", DB_NAME,
        "--language=java",
        "--source-root=.",
        "--command=mvn -DskipTests -Dspotless.check.skip=true -Dspotless.apply.skip=true clean compile"
    ], check=True)


# ===============================
# STEP 3 — Run CodeQL Analysis
# ===============================

def run_codeql_analysis():
    print("Running CodeQL analysis...")

    subprocess.run([
        "codeql", "database", "analyze", DB_NAME,
        "codeql/java-queries",
        "--format=sarifv2.1.0",
        f"--output={SARIF_FILE}"
    ], check=True)


# ===============================
# STEP 4 — Parse SARIF
# ===============================

def extract_alerts_for_files(changed_files):
    with open(SARIF_FILE) as f:
        sarif = json.load(f)

    alerts = []

    results = sarif["runs"][0].get("results", [])

    for r in results:
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

        for file in changed_files:
            if uri.endswith(Path(file).name):
                line = r["locations"][0]["physicalLocation"]["region"]["startLine"]
                rule = r["ruleId"]

                alerts.append({
                    "file": uri,
                    "line": line,
                    "ruleId": rule
                })

    return alerts


# ===============================
# STEP 5 — Feature Builder
# ===============================

def build_features_for_alerts(alerts):
    from collections import defaultdict
    from pathlib import Path
    import pandas as pd

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

    input_keywords = [
        "request.getParameter",
        "getParameter(",
        "Scanner",
        "BufferedReader",
        "readLine(",
        "request.getHeader"
    ]

    alerts_per_file = defaultdict(int)

    for alert in alerts:
        test_id = Path(alert["file"]).stem
        alerts_per_file[test_id] += 1

    feature_rows = []

    for alert in alerts:
        test_id = Path(alert["file"]).stem
        file_path = alert["file"]

        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
        except:
            continue

        file_len = len(lines)
        line_number = alert["line"]
        alert_count = alerts_per_file[test_id]

        density = alert_count / file_len if file_len > 0 else 0

        snippet_start = max(0, line_number - 5)
        snippet_end = min(file_len, line_number + 5)
        snippet = "".join(lines[snippet_start:snippet_end])
        snippet_length = len(snippet)

        has_dangerous_api = int(any(kw in snippet for kw in dangerous_keywords))
        has_user_input = int(any(kw in snippet for kw in input_keywords))

        feature_rows.append({
            "ruleId": alert["ruleId"],
            "line": line_number,
            "alert_count": alert_count,
            "file_length": file_len,
            "density": density,
            "snippet_length": snippet_length,
            "has_dangerous_api": has_dangerous_api,
            "has_user_input": has_user_input
        })

    df = pd.DataFrame(feature_rows)

    df = df[[
        "ruleId",
        "line",
        "alert_count",
        "file_length",
        "density",
        "snippet_length",
        "has_dangerous_api",
        "has_user_input"
    ]]

    return df
# ===============================
# STEP 6 — ML Filtering
# ===============================

import joblib
import pandas as pd

def ml_filter(alerts):
    if not alerts:
        return []

    model = joblib.load("rf_model.pkl")
    trained_columns = joblib.load("rf_feature_columns.pkl")

    X = build_features_for_alerts(alerts)

    # One-hot encode ruleId like training
    X = pd.get_dummies(X, columns=["ruleId"])

    # Add missing columns from training
    for col in trained_columns:
        if col not in X.columns:
            X[col] = 0

    # Remove extra columns not seen during training
    X = X[trained_columns]

    probs = model.predict_proba(X)

    confirmed = []

    for alert, prob in zip(alerts, probs):
        confidence = prob[1]

        if confidence >= 0.6:
            confirmed.append({
                "file": alert["file"],
                "line": alert["line"],
                "rule": alert["ruleId"],
                "confidence": round(float(confidence), 3),
                "needs_patch": True
            })

    return confirmed  
# ===============================
# MAIN AGENT
# ===============================

if __name__ == "__main__":

    print("\n=== Agentic Vulnerability Triage System ===\n")

    changed_files = get_changed_java_files()

    if not changed_files:
        print("No Java changes detected.")
        exit()

    print("Changed Java files:")
    for f in changed_files:
        print(" -", f)

    rebuild_codeql_database()
    run_codeql_analysis()

    alerts = extract_alerts_for_files(changed_files)

    if not alerts:
        print("\nNo vulnerabilities detected by static analysis.")
        exit()

    confirmed = ml_filter(alerts)

    print("\n=== FINAL TRIAGE RESULT ===\n")

    if not confirmed:
        print("No confirmed vulnerabilities after ML filtering.")
    else:
        for c in confirmed:
            print(f"File: {c['file']}")
            print(f"Line: {c['line']}")
            print(f"Rule: {c['rule']}")
            print(f"Confidence: {c['confidence']}")
            print("Needs Patch: YES")
            print("-" * 50)
