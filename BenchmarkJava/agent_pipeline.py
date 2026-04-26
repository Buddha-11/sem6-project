import os
import re
import sys
import subprocess
import json
import argparse
import joblib
import pandas as pd
from pathlib import Path
from collections import defaultdict
from groq import Groq

# ===============================
# CONFIG
# ===============================

DB_NAME       = "benchmark-db"
SARIF_FILE    = "agent_results.sarif"
MODEL_FILE    = "rf_model.pkl"
FEATURE_FILE  = "rf_feature_columns.pkl"

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY)

# ===============================
# STEP 1 — Detect Changed Files
# ===============================

def get_changed_java_files():
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            capture_output=True, text=True, check=True
        )
        files = result.stdout.strip().split("\n")
        return [f for f in files if f.endswith(".java")]
    except Exception as e:
        print(f"[WARN] git diff failed: {e}")
        return []

# ===============================
# STEP 2 — Rebuild CodeQL DB
# ===============================

def rebuild_codeql_database():
    if os.path.exists(DB_NAME):
        subprocess.run(["rm", "-rf", DB_NAME])
    print("[INFO] Rebuilding CodeQL database...")
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
    print("[INFO] Running CodeQL analysis...")
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
                alerts.append({"file": uri, "line": line, "ruleId": rule})

    return alerts

# ===============================
# STEP 5 — Feature Builder
# ===============================

def build_features_for_alerts(alerts):
    dangerous_keywords = [
        "Runtime.getRuntime", "exec(", "execute(",
        "Statement", "PreparedStatement", "eval(",
        "FileInputStream", "FileOutputStream"
    ]
    input_keywords = [
        "request.getParameter", "getParameter(",
        "Scanner", "BufferedReader",
        "readLine(", "request.getHeader"
    ]

    alerts_per_file = defaultdict(int)
    for alert in alerts:
        alerts_per_file[Path(alert["file"]).stem] += 1

    feature_rows = []
    for alert in alerts:
        file_path = alert["file"]
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
        except Exception:
            continue

        file_len    = len(lines)
        line_number = alert["line"]
        alert_count = alerts_per_file[Path(file_path).stem]
        density     = alert_count / file_len if file_len > 0 else 0

        s_start = max(0, line_number - 5)
        s_end   = min(file_len, line_number + 5)
        snippet = "".join(lines[s_start:s_end])

        feature_rows.append({
            "ruleId":            alert["ruleId"],
            "line":              line_number,
            "alert_count":       alert_count,
            "file_length":       file_len,
            "density":           density,
            "snippet_length":    len(snippet),
            "has_dangerous_api": int(any(k in snippet for k in dangerous_keywords)),
            "has_user_input":    int(any(k in snippet for k in input_keywords)),
        })

    df = pd.DataFrame(feature_rows)
    return df[["ruleId", "line", "alert_count", "file_length",
               "density", "snippet_length", "has_dangerous_api", "has_user_input"]]

# ===============================
# STEP 6 — ML Filtering
# ===============================

def ml_filter(alerts):
    if not alerts:
        return []

    model           = joblib.load(MODEL_FILE)
    trained_columns = joblib.load(FEATURE_FILE)

    X = build_features_for_alerts(alerts)
    X = pd.get_dummies(X, columns=["ruleId"])

    for col in trained_columns:
        if col not in X.columns:
            X[col] = 0
    X = X[trained_columns]

    probs     = model.predict_proba(X)
    confirmed = []

    for alert, prob in zip(alerts, probs):
        confidence = prob[1]
        if confidence >= 0.6:
            confirmed.append({
                "file":       alert["file"],
                "line":       alert["line"],
                "rule":       alert["ruleId"],
                "confidence": round(float(confidence), 3),
                "needs_patch": True,
            })

    return confirmed

# ===============================
# STEP 7 — LLM Patch Generation
# ===============================

def get_code_snippet(file_path, line_number, context=5):
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
        start = max(0, line_number - context)
        end   = min(len(lines), line_number + context)
        return "".join(lines[start:end])
    except Exception:
        return ""

def strip_code_fences(text: str) -> str:
    """Remove markdown code fences that LLMs often wrap responses in."""
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text)
    return text.strip()

def generate_patch_llm(alert: dict, full_file: bool = False) -> str:
    """
    Call Groq LLM to generate a fix.
    full_file=False  → snippet-level patch (iterations 1 to N-1)
    full_file=True   → return the entire corrected file (last iteration)
    """
    if full_file:
        try:
            with open(alert["file"], "r") as f:
                content = f.read()
        except Exception as e:
            return f"LLM Error: cannot read file: {e}"

        prompt = (
            "You are a secure Java code expert.\n"
            f"The following file has a vulnerability on approximately line {alert['line']}.\n"
            f"Detected rule: {alert['rule']}\n\n"
            "Fix ALL vulnerabilities and return ONLY the complete corrected Java file.\n"
            "Do NOT include markdown, code fences, or any explanation.\n\n"
            f"{content}"
        )
    else:
        snippet = get_code_snippet(alert["file"], alert["line"])
        prompt = (
            "You are a secure Java code expert.\n"
            f"Rule: {alert['rule']}\n"
            f"Vulnerable code (around line {alert['line']}):\n\n"
            f"{snippet}\n\n"
            "Return ONLY the fixed code snippet. No markdown, no fences, no explanation."
        )

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a secure Java expert. Return only fixed code."},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.2,
        )
        return strip_code_fences(response.choices[0].message.content)
    except Exception as e:
        return f"LLM Error: {e}"

# ===============================
# STEP 8 — Apply Patch to File
# ===============================

def apply_snippet_patch(file_path: str, line_number: int, patch_text: str, context: int = 5) -> bool:
    """Replace ±context lines around the vulnerability with the patched snippet."""
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()

        start = max(0, line_number - context - 1)
        end   = min(len(lines), line_number + context)

        patch_lines = patch_text.splitlines(keepends=True)
        if patch_lines and not patch_lines[-1].endswith("\n"):
            patch_lines[-1] += "\n"

        new_lines = lines[:start] + patch_lines + lines[end:]

        with open(file_path, "w") as f:
            f.writelines(new_lines)

        print(f"  ✓ Snippet patch applied → {file_path} (replaced lines {start+1}–{end})")
        return True
    except Exception as e:
        print(f"  ✗ Snippet patch failed: {e}")
        return False

def apply_full_file_patch(file_path: str, patch_text: str) -> bool:
    """Overwrite the entire file with the LLM-corrected version."""
    try:
        with open(file_path, "w") as f:
            f.write(patch_text)
            if not patch_text.endswith("\n"):
                f.write("\n")
        print(f"  ✓ Full-file patch applied → {file_path}")
        return True
    except Exception as e:
        print(f"  ✗ Full-file patch failed: {e}")
        return False

# ===============================
# STEP 9 — Save JSON Report
# ===============================

def save_results_json(results: list, filename: str = "final_results.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[INFO] Report saved → {filename}")

# ===============================
# STEP 10 — Agentic Loop
# ===============================

def run_agentic_loop(changed_files: list, max_iterations: int = 3) -> tuple:
    """
    Self-healing loop:
      • Iterations 1 … (max-1) : snippet-level patching
      • Iteration max           : full-file patching (last resort)
    Returns (remaining_vulns, is_clean: bool)
    """
    DIVIDER = "=" * 58

    for iteration in range(1, max_iterations + 1):
        print(f"\n{DIVIDER}")
        print(f"  AGENTIC LOOP — Iteration {iteration} / {max_iterations}")
        print(f"{DIVIDER}\n")

        rebuild_codeql_database()
        run_codeql_analysis()

        alerts = extract_alerts_for_files(changed_files)
        if not alerts:
            print("✅  No vulnerabilities found by static analysis. Code is clean!")
            save_results_json([], "final_results.json")
            return [], True

        confirmed = ml_filter(alerts)
        if not confirmed:
            print("✅  No confirmed vulnerabilities after ML triage. Code is clean!")
            save_results_json([], "final_results.json")
            return [], True

        print(f"⚠   {len(confirmed)} confirmed vulnerability/ies.\n")

        use_full_file  = (iteration == max_iterations)
        strategy_label = "full-file" if use_full_file else "snippet"
        print(f"--- Patching in [{strategy_label}] mode ---\n")

        for vuln in confirmed:
            print(f"  File : {vuln['file']}")
            print(f"  Line : {vuln['line']}  Rule: {vuln['rule']}  Confidence: {vuln['confidence']}")

            patch = generate_patch_llm(vuln, full_file=use_full_file)
            if patch.startswith("LLM Error"):
                print(f"  ✗ {patch}")
                vuln.update({"patch": None, "patch_status": "llm_error", "patch_strategy": strategy_label})
                continue

            if use_full_file:
                success = apply_full_file_patch(vuln["file"], patch)
            else:
                success = apply_snippet_patch(vuln["file"], vuln["line"], patch)

            vuln.update({
                "patch":          patch,
                "patch_strategy": strategy_label,
                "patch_status":   "applied" if success else "failed",
            })
            print()

        save_results_json(confirmed, f"patch_iteration_{iteration}.json")

    # ── Final verification scan after all iterations ──
    print(f"\n{DIVIDER}")
    print("  FINAL VERIFICATION SCAN")
    print(f"{DIVIDER}\n")

    rebuild_codeql_database()
    run_codeql_analysis()

    final_alerts    = extract_alerts_for_files(changed_files)
    final_confirmed = ml_filter(final_alerts) if final_alerts else []

    if not final_confirmed:
        print("✅  All vulnerabilities resolved! Code is clean.")
        save_results_json([], "final_results.json")
        return [], True

    print(f"❌  {len(final_confirmed)} vulnerability/ies remain after {max_iterations} iteration(s).")
    save_results_json(final_confirmed, "final_results.json")
    return final_confirmed, False

# ===============================
# MAIN
# ===============================

def main():
    parser = argparse.ArgumentParser(
        description="Agentic Vulnerability Triage & Patching Pipeline"
    )
    parser.add_argument(
        "--mode",
        choices=["full", "patch-loop"],
        default="full",
        help="full: scan+triage+report  |  patch-loop: self-healing agentic loop",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Max patch-then-rescan cycles (default: 3)",
    )
    parser.add_argument(
        "--changed-files",
        type=str,
        default="",
        help="Comma-separated list of changed .java files (overrides git diff)",
    )
    args = parser.parse_args()

    # ── Resolve changed files ──
    if args.changed_files:
        changed_files = [f.strip() for f in args.changed_files.split(",") if f.strip()]
    else:
        changed_files = get_changed_java_files()

    print("\n=== Agentic Vulnerability Triage System ===\n")

    if not changed_files:
        print("[INFO] No Java changes detected. Nothing to scan.")
        sys.exit(0)

    print("Changed Java files:")
    for f in changed_files:
        print(f"  - {f}")

    # ── Dispatch mode ──
    if args.mode == "patch-loop":
        remaining, is_clean = run_agentic_loop(
            changed_files, max_iterations=args.max_iterations
        )
        sys.exit(0 if is_clean else 1)

    else:  # mode == "full" (original behaviour)
        rebuild_codeql_database()
        run_codeql_analysis()

        alerts = extract_alerts_for_files(changed_files)
        if not alerts:
            print("\n[INFO] No vulnerabilities detected by static analysis.")
            sys.exit(0)

        confirmed = ml_filter(alerts)

        print("\n=== FINAL TRIAGE RESULT ===\n")
        if not confirmed:
            print("No confirmed vulnerabilities after ML filtering.")
        else:
            for c in confirmed:
                print(f"File:       {c['file']}")
                print(f"Line:       {c['line']}")
                print(f"Rule:       {c['rule']}")
                print(f"Confidence: {c['confidence']}")
                print(f"Needs Patch: YES")
                print("-" * 50)

        save_results_json(confirmed)


if __name__ == "__main__":
    main()