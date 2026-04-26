#!/usr/bin/env bash
# ============================================================
#  Jenkins Local Setup Script
#  Downloads Jenkins WAR and starts it on port 8080.
#  All tools (CodeQL, Python, Maven) come from the host PATH.
# ============================================================
set -euo pipefail

JENKINS_VERSION="2.504"
JENKINS_WAR="jenkins-${JENKINS_VERSION}.war"
JENKINS_HOME="${HOME}/.jenkins-sem6"
JENKINS_PORT="8080"
DOWNLOAD_URL="https://get.jenkins.io/war/${JENKINS_VERSION}/jenkins.war"

# ── 1. Check Java ─────────────────────────────────────────
if ! command -v java &>/dev/null; then
  echo "[ERROR] Java is not installed. Please install JDK 17+."
  exit 1
fi
JAVA_VER=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
echo "[INFO] Java version: ${JAVA_VER}"

# ── 2. Download Jenkins WAR ────────────────────────────────
if [[ ! -f "${JENKINS_WAR}" ]]; then
  echo "[INFO] Downloading Jenkins ${JENKINS_VERSION}..."
  curl -fsSL -o "${JENKINS_WAR}" "${DOWNLOAD_URL}"
  echo "[INFO] Download complete."
else
  echo "[INFO] Jenkins WAR already present: ${JENKINS_WAR}"
fi

# ── 3. Set JENKINS_HOME ────────────────────────────────────
export JENKINS_HOME="${JENKINS_HOME}"
mkdir -p "${JENKINS_HOME}"

# ── 4. Skip setup wizard for first run ────────────────────
# (You can remove --argumentsRealm flags after initial login)
echo "[INFO] Starting Jenkins at http://localhost:${JENKINS_PORT}"
echo "[INFO] JENKINS_HOME = ${JENKINS_HOME}"
echo ""
echo "  Next steps:"
echo "  1. Open http://localhost:${JENKINS_PORT} in your browser."
echo "  2. Retrieve the initial admin password with:"
echo "       cat ${JENKINS_HOME}/secrets/initialAdminPassword"
echo "  3. Install suggested plugins."
echo "  4. Go to Manage Jenkins → Configure System → Environment variables"
echo "     and add:  GROQ_API_KEY = <your key>"
echo "  5. Create a Pipeline job → 'Pipeline script from SCM'"
echo "     SCM: Git  |  Repository URL: file:///home/arpit/Github/sem6-project"
echo "     Script Path: Jenkinsfile"
echo ""

# ── 5. Launch ─────────────────────────────────────────────
java \
  -DJENKINS_HOME="${JENKINS_HOME}" \
  -Djenkins.install.runSetupWizard=true \
  -jar "${JENKINS_WAR}" \
  --httpPort="${JENKINS_PORT}"
