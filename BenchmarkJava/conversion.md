# Data Conversion Pipeline: From Raw Alerts to Enhanced Machine Learning Features

This document explains how raw static analysis results (`alerts.csv`) are transformed into an enriched, actionable dataset (`ml_dataset_enhanced.csv`) used by our Machine Learning triage model. 

## The Objective
Static analysis tools (like CodeQL) output raw data containing a vulnerability rule, a file path, and a line number. However, this raw data lacks the **context** necessary for a machine learning model to distinguish between a true vulnerability and a false positive. 

Our conversion pipeline (within `agent_pipeline.py`) takes this raw data and performs **Feature Engineering**—extracting contextual clues from the source code itself to give the ML model a clearer picture of the code surrounding the alert.

---

## End-to-End Example of the Conversion

To visualize how the conversion happens, let's trace a vulnerability from its raw detection in CodeQL to its final feature representation.

### 1. The Raw Input (`alerts.csv`)
CodeQL scans the repository and finds two potential SQL Injection issues in the same file. It outputs the following raw data:
```csv
ruleId,file,line,message
java/sql-injection,src/main/java/.../BenchmarkTest00010.java,42,This SQL query is vulnerable.
java/sql-injection,src/main/java/.../BenchmarkTest00010.java,55,This SQL query is vulnerable.
```
*Note: The machine learning pipeline does not have enough information here. It only knows the file and the line, but has no idea what the code actually looks like.*

### 2. The Source Code Context (`BenchmarkTest00010.java`)
The pipeline script (`agent_pipeline.py`) opens the actual Java file. Let's assume the file has **100 total lines**, and the code around line 42 looks like this:

```java
39: public void doPost(HttpServletRequest request, HttpServletResponse response) {
40:     String param = request.getParameter("id"); // User input source!
41:     Connection conn = Database.getConnection();
42:     Statement statement = conn.createStatement(); // The alert is triggered here
43:     ResultSet rs = statement.executeQuery("SELECT * FROM users WHERE id = " + param);
44:     // ...
45: }
```

### 3. The Enriched Output (`ml_dataset_enhanced.csv`)
The pipeline analyzes the raw alert and the source code, creating the following row of features for the alert on line 42:

```csv
ruleId,line,alert_count,file_length,density,snippet_length,has_dangerous_api,has_user_input,label
java/sql-injection,42,2,100,0.02,285,1,1,1
```

**How did the pipeline arrive at these numbers?**
*   **`ruleId`**: `java/sql-injection` (Carried over from `alerts.csv`)
*   **`line`**: `42` (Carried over from `alerts.csv`)
*   **`alert_count`**: `2` (Because `alerts.csv` listed this file twice—once on line 42, and once on line 55).
*   **`file_length`**: `100` (The total number of lines in `BenchmarkTest00010.java`).
*   **`density`**: `0.02` (Calculated as `alert_count / file_length`, which is `2 / 100`).
*   **`snippet_length`**: `285` (The script extracted lines 37 through 47, combined them into a single block of text, and counted exactly 285 characters including spaces).
*   **`has_dangerous_api`**: `1` (The script detected the keyword `"Statement"` in the extracted code snippet).
*   **`has_user_input`**: `1` (The script detected the keyword `"request.getParameter"` in the extracted code snippet).
*   **`label`**: `1` (This is the ground truth telling the model this is an actual, exploitable vulnerability, mapped from the historical dataset).

---

## The Features Explained

The `ml_dataset_enhanced.csv` contains the following fields. Here is exactly how each one is calculated from the raw source code.

### 1. `ruleId` (Inherited)
*   **What it is:** The exact CodeQL rule that triggered the alert (e.g., `java/stack-trace-exposure`).
*   **How it's created:** Inherited directly from the raw `alerts.csv` / SARIF file.

### 2. `line` (Inherited)
*   **What it is:** The exact line number in the source file where the vulnerability was flagged.
*   **How it's created:** Inherited directly from the raw `alerts.csv` / SARIF file.

### 3. `alert_count` (Calculated)
*   **What it is:** The total number of alerts (vulnerabilities) found within that specific Java file, regardless of rule type.
*   **How it's created:** Before processing the features, the script groups all alerts by their filename. It then simply counts the total number of times a specific file appears in the list of alerts.
    ```python
    # Logic in agent_pipeline.py
    alerts_per_file = defaultdict(int)
    for alert in alerts:
        alerts_per_file[Path(alert["file"]).stem] += 1
    ```
    *Example: If `BenchmarkTest00020.java` has 3 `stack-trace-exposure` alerts and 2 `sql-injection` alerts, the `alert_count` for all 5 of these rows will be `5`.*

### 4. `file_length` (Calculated)
*   **What it is:** The total number of **lines of code** in the entire Java file where the alert occurred.
*   **How it's created:** The script opens the Java file and counts the total number of lines.
    ```python
    file_len = len(lines)
    ```

### 5. `density` (Calculated)
*   **What it is:** The concentration of vulnerabilities within the file.
*   **How it's created:** It is the ratio of `alert_count` to `file_length`.
    ```python
    density = alert_count / file_len
    ```
    *Why it matters: A high density indicates a file that is heavily flagged, which might correlate with generally insecure coding practices.*

### 6. `snippet_length` (Calculated)
*   **What it is:** The total number of **characters** (not lines) in the extracted code block surrounding the vulnerability.
*   **How it's created:** The script extracts a "context window" of roughly 10 lines of code (5 lines before the alert, and 5 lines after). It joins these lines together into a single string and counts the total number of characters (including spaces and newlines).
    ```python
    s_start = max(0, line_number - 5)
    s_end   = min(file_len, line_number + 5)
    snippet = "".join(lines[s_start:s_end])
    snippet_length = len(snippet)
    ```
    *Note: Because this is measured in characters, `snippet_length` (e.g., 627) will naturally be a mathematically larger number than `file_length` (e.g., 151), which is measured in lines.*

### 7. `has_dangerous_api` (Calculated)
*   **What it is:** A boolean flag (`1` or `0`) indicating whether the code snippet contains known dangerous methods.
*   **How it's created:** The script searches the `snippet` string for specific keywords. If any are found, it outputs `1`; otherwise, `0`.
    ```python
    dangerous_keywords = ["Runtime.getRuntime", "exec(", "execute(", "Statement", "PreparedStatement", "eval(", "FileInputStream", "FileOutputStream"]
    has_dangerous_api = int(any(k in snippet for k in dangerous_keywords))
    ```

### 8. `has_user_input` (Calculated)
*   **What it is:** A boolean flag (`1` or `0`) indicating whether the code snippet contains methods typically used to read user input.
*   **How it's created:** Similar to the dangerous API check, the script scans the snippet for specific input-related keywords.
    ```python
    input_keywords = ["request.getParameter", "getParameter(", "Scanner", "BufferedReader", "readLine(", "request.getHeader"]
    has_user_input = int(any(k in snippet for k in input_keywords))
    ```
    *Why it matters: Vulnerabilities often require user input to be exploitable. Flagging the presence of user input near an alert increases the model's confidence that the vulnerability is genuine.*

---
## Summary of the Pipeline Workflow
1. **Raw Input:** CodeQL outputs a SARIF file (which translates to the data seen in `alerts.csv`).
2. **Context Gathering:** For each alert, `agent_pipeline.py` opens the corresponding `.java` file.
3. **Feature Extraction:** It calculates the size of the file, the density of alerts, extracts a code snippet around the vulnerable line, measures that snippet, and scans it for dangerous keywords.
4. **Enhanced Output:** This enriched data is packaged into `ml_dataset_enhanced.csv` (or passed directly to the model in memory) where the Random Forest algorithm uses these features to confidently predict whether the alert is a True Positive or a False Positive.
