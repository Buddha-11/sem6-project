🛡️ Agentic AI for Intelligent Vulnerability Triage & Patch Suggestion  
### Hybrid Static Analysis + Machine Learning Security Pipeline

---

## 📌 Project Overview

This project implements an **agentic vulnerability detection and triage system** for Java codebases.

It integrates:

- ✅ CodeQL static analysis
- ✅ Supervised Machine Learning filtering (Random Forest)
- 🔄 (Planned) LLM-based patch generation

The system monitors code changes, detects potential vulnerabilities, filters false positives using ML, and determines whether a file requires patching — along with a confidence score.

---

# 🎯 What Problem Does This Solve?

Static analysis tools like CodeQL are powerful but produce:

- ❌ High false positive rates  
- ❌ Alert fatigue  
- ❌ Manual triage burden  

This project introduces:

A hybrid AI-driven filtering layer that improves precision while maintaining recall.

Instead of blindly trusting static results, we:

1. Extract contextual features around alerts
2. Train a classifier on labeled benchmark data
3. Predict whether each alert is a real vulnerability
4. Provide a confidence score for remediation

---

# 🧠 Core Architecture

Git Commit Change  
↓  
Change Detection (Git Diff)  
↓  
CodeQL Static Scan  
↓  
Feature Extraction  
↓  
Random Forest Classifier  
↓  
Final Vulnerability Triage Output  

---

# 🔬 Research & Novelty Perspective

### 🔹 Hybrid Intelligence Model

Unlike traditional tools that:

- Use static rules only
- Or use LLMs without grounding

This system:

- Uses static analysis for sound detection
- Uses ML for probabilistic filtering
- Prepares ground for agentic remediation

### 🔹 Alert-Level ML Filtering

We trained a supervised model on:

- OWASP Benchmark labeled results
- CodeQL findings
- Contextual code features

The model learns patterns like:

- Presence of dangerous APIs
- User input indicators
- Snippet density
- Alert frequency per file

### 🔹 Incremental Security Agent

The pipeline operates at:

- File-level change granularity
- Commit-level detection
- Database reuse with incremental CodeQL

This is closer to a real-world CI security bot.

---

# 📊 Current Performance (Enhanced ML Dataset)

After adding contextual code features:

Accuracy: 82%  
Precision (Vulnerable class): 0.86  
Recall (Vulnerable class): 0.88  
F1 Score: 0.87  

This significantly reduces false positives compared to raw static output.

---

# 📁 Repository Structure

BenchmarkJava/
│
├── agent_pipeline.py              # Main security agent
├── build_ml_dataset.py            # Dataset generation with context features
├── train_random_forest.py         # ML training script
├── rf_model.pkl                   # Trained classifier
├── ml_dataset_enhanced.csv        # Final ML dataset
├── labeled_static_dataset.csv     # Ground truth benchmark data
├── .gitignore
└── README.md

Note: CodeQL database and logs are intentionally excluded from Git.

---

# ⚙️ Setup Instructions

## 1️⃣ Clone Repository

git clone https://github.com/<your-username>/sem6-project.git  
cd sem6-project/BenchmarkJava  

---

## 2️⃣ Create Python Virtual Environment

python3 -m venv venv  
source venv/bin/activate  

Install dependencies:

pip install -r requirements.txt  

If no requirements file exists:

pip install pandas scikit-learn joblib numpy  

---

## 3️⃣ Install CodeQL

Download from:

https://github.com/github/codeql-cli-binaries/releases  

Extract and add to PATH:

export PATH=$PATH:/path/to/codeql  

Verify:

codeql --version  

---

## 4️⃣ Build CodeQL Database

From BenchmarkJava/:

rm -rf benchmark-db  

codeql database create benchmark-db \
  --language=java \
  --source-root=. \
  --command="mvn -q -DskipTests -Dspotless.check.skip=true compile"

If Maven errors occur, ensure:

- spotless plugin is skipped  
- origin/master references removed if necessary  

---

## 5️⃣ Run CodeQL Analysis

codeql database analyze benchmark-db \
  codeql/java-queries \
  --format=sarif-latest \
  --output=results.sarif  

---

## 6️⃣ Train ML Model (If Needed)

Rebuild dataset:

python build_ml_dataset.py  

Train model:

python train_random_forest.py  

Ensure rf_model.pkl is generated.

---

## 7️⃣ Run Agentic Pipeline

python agent_pipeline.py  

Example Output:

=== FINAL TRIAGE RESULT ===

File: src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java  
Line: 57  
Rule: java/sql-injection  
Confidence: 0.735  
Needs Patch: YES  

---

# 🤖 What the Agent Currently Does

✔ Detects changed Java files  
✔ Runs CodeQL on updated database  
✔ Extracts alert-level features  
✔ Applies Random Forest classifier  
✔ Outputs vulnerability decision + confidence  

---

# 🚧 Planned Next Phase

### 🔹 Patch Generation Module

- LLM-based remediation suggestions  
- Context-aware fix generation  
- Confidence-aware patch thresholding  

### 🔹 CI Integration

- GitHub Actions automation  
- Auto triage on PR  
- Security comment bot  

### 🔹 Active Learning Loop

- Use developer feedback  
- Retrain ML model  
- Continuous improvement  

---

# 🏆 Academic Contribution Angle

This project demonstrates:

- Practical hybrid AI in software security  
- Reduction of false positives in static analysis  
- Agentic vulnerability triage design  
- Dataset engineering for security ML  
- Real-world incremental scanning system  

It can evolve into:

- A publishable research prototype  
- A security CI plugin  
- A DevSecOps automation tool  

---

# 📌 Current Status (Mid-Term Evaluation)

Component                               Status  
CodeQL Integration                      ✅ Complete  
ML Dataset Engineering                  ✅ Complete  
Random Forest Filtering                 ✅ Working  
Incremental Commit Detection            ✅ Working  
Confidence-Based Output                 ✅ Working  
LLM Patch Generation                    🔄 Planned  

---

# 📜 License

Academic / Research Use  

---

# 👨‍💻 Authors

Arpit Anand IIT2023170
Snehal Gupta IIT2023169
Ansh Namdeo IIT2023141
