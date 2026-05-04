// ============================================================
//  Agentic Vulnerability Scan + Auto-Patch — Jenkins Pipeline
//  SAST: CodeQL (agentic patch loop)
//  DAST: OWASP ZAP baseline scan
// ============================================================
pipeline {

    agent any

    environment {
        // ── Add CodeQL to PATH ──
        CODEQL_HOME       = "/home/arpit/Downloads/codeql-linux64/codeql"
        PATH              = "${CODEQL_HOME}:${env.PATH}"

        // ── Fix Python output buffering so timestamps are accurate ──
        PYTHONUNBUFFERED  = "1"

        // ── Groq key — set in:
        //    Manage Jenkins → Configure System → Environment variables
        //    Name: GROQ_API_KEY   Value: <your key>

        MAX_ITERATIONS = "3"
        PIPELINE_DIR   = "BenchmarkJava"

        // ── Git identity for auto-patch commits ──
        GIT_AUTHOR_NAME  = "Jenkins Auto-Patch"
        GIT_AUTHOR_EMAIL = "jenkins@localhost"

        // ── ZAP config ──
        ZAP_APP_PORT     = "8443"
        ZAP_APP_URL      = "https://localhost:8443/benchmark/"
    }

    options {
        timestamps()
        timeout(time: 120, unit: "MINUTES")   // extended for ZAP startup+scan
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
                        echo "ℹ  No Java files changed in this commit — skipping SAST scan."
                        currentBuild.result = "SUCCESS"
                        env.SKIP_SCAN     = "true"
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
        stage("SAST: CodeQL + Agentic Patch Loop") {
        // ─────────────────────────────────────────────
            when { expression { env.SKIP_SCAN == "false" } }
            steps {
                dir(env.PIPELINE_DIR) {
                    script {
                        def exitCode = sh(
                            script: """
                                . venv/bin/activate
                                python3 -u agent_pipeline.py \\
                                    --mode patch-loop \\
                                    --max-iterations ${MAX_ITERATIONS} \\
                                    --changed-files "${env.CHANGED_FILES}"
                            """,
                            returnStatus: true
                        )

                        env.PIPELINE_EXIT = exitCode.toString()

                        if (exitCode == 0) {
                            echo "✅  SAST clean — all CodeQL vulnerabilities patched."
                        } else {
                            currentBuild.result = "UNSTABLE"
                            echo "⚠  SAST: CodeQL vulnerabilities remain after ${MAX_ITERATIONS} iterations."
                        }
                    }
                }
            }
        }

        // ─────────────────────────────────────────────
        stage("Commit Auto-Patch to Repo") {
        // ─────────────────────────────────────────────
            // Only run when the SAST loop exited clean
            when {
                allOf {
                    expression { env.SKIP_SCAN == "false" }
                    expression { env.PIPELINE_EXIT == "0" }
                }
            }
            steps {
                script {
                    def diffOutput = sh(
                        script: "git diff --stat HEAD",
                        returnStdout: true
                    ).trim()

                    if (!diffOutput) {
                        echo "ℹ  No file changes to commit (patch may have matched original)."
                    } else {
                        echo "=== Files changed by agentic patch ===\n${diffOutput}"
                        sh "git diff HEAD"

                        def pushCode = sh(
                            script: """
                                git config user.email "${GIT_AUTHOR_EMAIL}"
                                git config user.name  "${GIT_AUTHOR_NAME}"
                                git add -A
                                git commit -m "auto-patch: vulnerability fixed by agentic pipeline [build #${env.BUILD_NUMBER}]"
                                git push origin HEAD:main
                            """,
                            returnStatus: true
                        )
                        if (pushCode == 0) {
                            echo "✔  Patched files committed and pushed to main."
                        } else {
                            echo "⚠  Push failed (exit ${pushCode}). Patch applied locally but not pushed."
                            currentBuild.result = "UNSTABLE"
                        }
                    }
                }
            }
        }

        // ─────────────────────────────────────────────
        stage("DAST: OWASP ZAP Scan") {
        // ─────────────────────────────────────────────
            // Run DAST regardless of SAST result — always valuable to scan.
            // Uses zap_scan.py which handles the full lifecycle:
            //   build WAR → start Cargo/Tomcat → ZAP Docker scan → stop → parse
            steps {
                dir(env.PIPELINE_DIR) {
                    script {
                        // Pull ZAP image first (cached after first run)
                        sh "docker pull ghcr.io/zaproxy/zaproxy:stable"

                        // Ensure any previous Tomcat on this port is dead
                        sh "fuser -k ${ZAP_APP_PORT}/tcp 2>/dev/null || true"

                        def zapExit = sh(
                            script: """
                                . venv/bin/activate
                                python3 -u zap_scan.py
                            """,
                            returnStatus: true
                        )

                        env.ZAP_EXIT = zapExit.toString()

                        if (zapExit == 0) {
                            echo "✅  DAST: ZAP scan completed."
                        } else {
                            echo "⚠  DAST: ZAP scan exited with code ${zapExit} — check zap_report.html"
                            // Don't fail the build — ZAP findings are advisory
                            if (currentBuild.result != "FAILURE") {
                                currentBuild.result = "UNSTABLE"
                            }
                        }

                        // Print ZAP summary inline in build log
                        if (fileExists("zap_results.json")) {
                            def zapJson = readFile("zap_results.json")
                            def zapFindings = readJSON text: zapJson
                            def highCount = zapFindings.count { it.riskcode == 3 }
                            def medCount  = zapFindings.count { it.riskcode == 2 }
                            echo "=== ZAP Results ==="
                            echo "  HIGH   : ${highCount}"
                            echo "  MEDIUM : ${medCount}"
                            echo "  TOTAL  : ${zapFindings.size()}"
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
                        // SAST report
                        def finalJson = fileExists("final_results.json")
                            ? readFile("final_results.json")
                            : "[]"
                        echo "=== SAST Final Report (CodeQL) ===\n${finalJson}"

                        // DAST report summary
                        if (fileExists("zap_results.json")) {
                            echo "=== DAST Report (ZAP) — see archived zap_report.html for full details ==="
                        }
                    }
                }
            }
        }

    }   // end stages

    post {
        always {
            dir(env.PIPELINE_DIR) {
                archiveArtifacts(
                    artifacts:         "*.sarif, *.json, zap_report.html",
                    allowEmptyArchive: true,
                    fingerprint:       true
                )
            }
            echo "📦  Artifacts archived (SARIF, JSON reports, ZAP HTML)."
        }

        success {
            echo "🎉  Build SUCCESS — code is vulnerability-free, patches committed."
        }

        unstable {
            echo "⚠  Build UNSTABLE — some vulnerabilities remain or ZAP found issues. Review reports."
        }

        failure {
            // Ensure Tomcat is killed even on pipeline failure
            sh "fuser -k ${ZAP_APP_PORT}/tcp 2>/dev/null || true"
            echo "💥  Build FAILED — pipeline error. Check the logs above."
        }
    }

}
