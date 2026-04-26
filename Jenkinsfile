// ============================================================
//  Agentic Vulnerability Scan + Auto-Patch — Jenkins Pipeline
// ============================================================
pipeline {

    agent any

    environment {
        // ── Add CodeQL to PATH (matches the path you exported locally) ──
        CODEQL_HOME = "/home/arpit/Downloads/codeql-linux64/codeql"
        PATH        = "${CODEQL_HOME}:${env.PATH}"

        // ── Groq key — set this in:
        //    Manage Jenkins → Configure System → Global properties → Environment variables
        //    Name: GROQ_API_KEY   Value: <your key>
        // Jenkins will inherit it automatically; no change needed here.

        MAX_ITERATIONS = "3"
        PIPELINE_DIR   = "BenchmarkJava"
    }

    options {
        timestamps()
        timeout(time: 90, unit: "MINUTES")   // full loop can take a while
        ansiColor("xterm")
    }

    stages {

        // ─────────────────────────────────────────────
        stage("Checkout") {
        // ─────────────────────────────────────────────
            steps {
                checkout scm
                echo "✔  Repository checked out."
            }
        }

        // ─────────────────────────────────────────────
        stage("Detect Changed Java Files") {
        // ─────────────────────────────────────────────
            steps {
                script {
                    def raw = sh(
                        script: "git diff --name-only HEAD~1 HEAD || true",
                        returnStdout: true
                    ).trim()

                    def javaFiles = raw.split("\n")
                                       .findAll { it.endsWith(".java") }
                                       .join(",")

                    if (!javaFiles) {
                        echo "ℹ  No Java files changed in this commit — skipping scan."
                        currentBuild.result = "SUCCESS"
                        // Use a custom variable to signal early exit to later stages
                        env.SKIP_SCAN = "true"
                        env.CHANGED_FILES = ""
                    } else {
                        env.SKIP_SCAN     = "false"
                        env.CHANGED_FILES = javaFiles
                        echo "Changed Java files:\n${javaFiles.replaceAll(',', '\n')}"
                    }
                }
            }
        }

        // ─────────────────────────────────────────────
        stage("Setup Python Environment") {
        // ─────────────────────────────────────────────
            when { expression { env.SKIP_SCAN == "false" } }
            steps {
                dir(env.PIPELINE_DIR) {
                    sh """
                        python3 -m venv venv
                        . venv/bin/activate
                        pip install -q --upgrade pip
                        pip install -q groq joblib pandas scikit-learn
                    """
                    echo "✔  Python environment ready."
                }
            }
        }

        // ─────────────────────────────────────────────
        stage("Agentic Scan + Patch Loop") {
        // ─────────────────────────────────────────────
            when { expression { env.SKIP_SCAN == "false" } }
            steps {
                dir(env.PIPELINE_DIR) {
                    script {
                        // Run the self-healing loop; exit code 0 = clean, 1 = vulns remain
                        def exitCode = sh(
                            script: """
                                . venv/bin/activate
                                python3 agent_pipeline.py \\
                                    --mode patch-loop \\
                                    --max-iterations ${MAX_ITERATIONS} \\
                                    --changed-files "${env.CHANGED_FILES}"
                            """,
                            returnStatus: true
                        )

                        env.PIPELINE_EXIT = exitCode.toString()

                        if (exitCode == 0) {
                            echo "✅  Pipeline exited CLEAN — all vulnerabilities patched."
                        } else {
                            // Mark unstable rather than hard-failing so artifacts are still saved
                            currentBuild.result = "UNSTABLE"
                            echo "⚠  Vulnerabilities remain after ${MAX_ITERATIONS} iterations."
                        }
                    }
                }
            }
        }

        // ─────────────────────────────────────────────
        stage("Publish Report") {
        // ─────────────────────────────────────────────
            when { expression { env.SKIP_SCAN == "false" } }
            steps {
                dir(env.PIPELINE_DIR) {
                    script {
                        // Pretty-print the final JSON summary
                        def finalJson = fileExists("final_results.json")
                            ? readFile("final_results.json")
                            : "[]"
                        echo "=== Final Vulnerability Report ===\n${finalJson}"
                    }
                }
            }
        }

    }   // end stages

    post {
        always {
            // Archive SARIF + every patch iteration JSON
            dir(env.PIPELINE_DIR) {
                archiveArtifacts(
                    artifacts:          "*.sarif, *.json",
                    allowEmptyArchive:  true,
                    fingerprint:        true
                )
            }
            echo "📦  Artifacts archived."
        }

        success {
            echo "🎉  Build SUCCESS — code is vulnerability-free."
        }

        unstable {
            echo "⚠  Build UNSTABLE — vulnerabilities persist. Review final_results.json."
        }

        failure {
            echo "💥  Build FAILED — pipeline error. Check the logs above."
        }
    }

}
