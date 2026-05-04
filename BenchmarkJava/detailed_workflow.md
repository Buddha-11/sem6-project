# Agentic Vulnerability Triage and Patching Pipeline: Detailed Workflow

This document provides a comprehensive, end-to-end technical breakdown of the automated vulnerability remediation pipeline. The system orchestrates static analysis, machine learning triage, and LLM-based self-healing code generation to create an autonomous security agent.

Below is the step-by-step breakdown of how the `agent_pipeline.py` script functions when running in `--mode patch-loop`.

---

## 1. Triggering and File Detection
*   **The Goal:** Identify which files need to be scanned to avoid scanning the entire repository unnecessarily.
*   **How it Works:** The `get_changed_java_files()` function executes a Git command (`git diff --name-only HEAD~1 HEAD`). This isolates exactly which `.java` files were modified in the most recent commit. Only these changed files will be targeted for patching.

## 2. Compilation and CodeQL Database Creation
*   **The Goal:** Prepare the codebase for deep static analysis.
*   **How it Works:** The function `rebuild_codeql_database()` removes any existing `benchmark-db` directory. It then uses the CodeQL CLI to create a new database by natively wrapping the build process (`mvn -DskipTests clean compile`). This step is critical: CodeQL requires a fully compiled abstract syntax tree (AST) to understand data flow (e.g., tracking a tainted user input from a controller down to a database query). If the code doesn't compile, CodeQL cannot analyze it.

## 3. Static Analysis Execution
*   **The Goal:** Scan the newly created database for security flaws.
*   **How it Works:** The `run_codeql_analysis()` function executes the standard `java-queries` suite against the `benchmark-db`. The output is generated and saved as a JSON file named `agent_results.sarif` (Static Analysis Results Interchange Format).

## 4. Alert Extraction and Parsing
*   **The Goal:** Extract actionable data from the massive, complex SARIF JSON file.
*   **How it Works:** `extract_alerts_for_files()` parses the SARIF file. It filters out everything except the alerts that occurred in the files identified in Step 1. For each relevant alert, it extracts three key pieces of information: 
    1.  The `ruleId` (the vulnerability type).
    2.  The `uri` (file path).
    3.  The `startLine` (where the vulnerability begins).

## 5. Feature Engineering (Context Gathering)
*   **The Goal:** Transform raw, context-less alerts into rich data points that a Machine Learning model can understand.
*   **How it Works:** The `build_features_for_alerts()` function opens the actual Java source code and calculates several metrics:
    *   **File Length & Alert Count:** It counts the total lines in the file and the total number of alerts CodeQL found in that file.
    *   **Density:** It calculates the vulnerability density (`alert_count / file_length`).
    *   **Snippet Analysis:** It extracts a block of code (±5 lines around the vulnerable line) and measures its exact length in characters (`snippet_length`).
    *   **Keyword Flags:** It scans the snippet for specific dangerous keywords (like `exec` or `Statement`) to trigger `has_dangerous_api`, and input keywords (like `request.getParameter`) to trigger `has_user_input`.

## 6. Machine Learning Triage
*   **The Goal:** Filter out "False Positives" so the LLM doesn't waste time or break code trying to fix things that aren't actually broken.
*   **How it Works:** The `ml_filter()` function loads a pre-trained Random Forest model (`rf_model.pkl`). It feeds the engineered features from Step 5 into the model. The model returns a probability score.
    *   If the confidence score is **>= 0.6 (60%)**, the alert is marked as "confirmed" and flagged for patching.
    *   Alerts below 60% confidence are ignored as false positives.

## 7. The Agentic Self-Healing Loop
*   **The Goal:** Automatically generate a code fix, apply it, and test it.
*   **How it Works:** The system iterates through the confirmed vulnerabilities in a loop (defaulting to 3 iterations).
    
    *   **Phase A: Snippet-Level Patch Generation**
        The system isolates the vulnerable code snippet and sends it to the Groq API (using the `llama-3.3-70b-versatile` model). The system prompt strictly instructs the LLM to return *only* valid Java code without any markdown or explanations.
    
    *   **Phase B: Patch Application & Compilation Validation (The Safety Net)**
        The `apply_snippet_patch()` function carefully splices the LLM's generated code back into the Java file, replacing the vulnerable lines. Immediately after, it calls `validate_compilation()` which runs `mvn clean compile`.
        *   **If compilation succeeds:** The patch is finalized.
        *   **If compilation fails:** The LLM made a mistake (e.g., a syntax error or missing import). The script automatically catches this, **reverts the file to its original state**, and marks the patch as failed.

    *   **Phase C: Full-File Escalation**
        If a snippet patch causes a compilation error, or if the pipeline is on its final iteration and the vulnerability still exists, the pipeline "escalates". It reads the *entire* file and sends it to the LLM (`full_file=True`). This gives the LLM maximum context to fix complex issues that span multiple methods or require new imports.

## 8. Final Verification Scan
*   **The Goal:** Ensure the repository is clean before finishing the pipeline.
*   **How it Works:** After all patching iterations are complete, the entire process loops back to Step 2. It rebuilds the CodeQL database on the newly patched code, runs the analysis, and performs ML filtering.
    *   If no vulnerabilities remain, it prints success (`Code is clean!`) and exits smoothly.
    *   If vulnerabilities persist, it saves them to `final_results.json` and exits with an error code, which can be used to fail a CI/CD build.
