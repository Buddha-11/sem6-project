#!/usr/bin/env python3
"""
zap_scan.py — OWASP ZAP DAST integration for the Benchmark pipeline.

Workflow:
  1. Build the Benchmark WAR (mvn package)
  2. Start Tomcat via Cargo in the background
  3. Wait for the app to be reachable
  4. Run ZAP baseline scan (Docker) against the live app
  5. Stop Tomcat
  6. Parse ZAP JSON report and print a summary
  7. Save findings to zap_results.json (same format as CodeQL alerts)

Exit code:
  0  — scan completed (alerts may still exist; check zap_results.json)
  1  — startup or scan infrastructure failure
"""

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error

# ── Config ──────────────────────────────────────────────────────────────────
APP_PORT      = 8443
APP_PROTOCOL  = "https"
APP_URL       = f"{APP_PROTOCOL}://localhost:{APP_PORT}/benchmark/"
APP_LOG       = "/tmp/benchmark_cargo.log"
APP_PID_FILE  = "/tmp/benchmark_cargo.pid"

ZAP_IMAGE     = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_WORK_DIR  = os.path.abspath(".")          # mounted into /zap/wrk inside container
ZAP_JSON_OUT  = "zap_report.json"
ZAP_HTML_OUT  = "zap_report.html"
ZAP_RESULTS   = "zap_results.json"            # normalised output consumed by pipeline

STARTUP_TIMEOUT_SEC = 180   # 3 min for Tomcat + WAR deployment
POLL_INTERVAL_SEC   = 5

# ── Helpers ──────────────────────────────────────────────────────────────────

def log(msg: str):
    print(f"[ZAP] {msg}", flush=True)


def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    log(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, **kwargs)


def build_war() -> bool:
    log("Building WAR (mvn package -DskipTests)…")
    result = run([
        "mvn", "-DskipTests",
        "-Dspotless.check.skip=true",
        "-Dspotless.apply.skip=true",
        "clean", "package",
    ])
    if result.returncode != 0:
        log("ERROR: WAR build failed.")
        return False
    log("WAR built OK.")
    return True


def start_app() -> subprocess.Popen:
    """Start Cargo/Tomcat in the background and return the Popen object."""
    log(f"Starting Benchmark app on port {APP_PORT} via Cargo…")

    # mvn initialize (needed for ESAPI config)
    run(["mvn", "-q",
         "-Dspotless.check.skip=true", "-Dspotless.apply.skip=true",
         "initialize"])

    with open(APP_LOG, "w") as log_file:
        proc = subprocess.Popen(
            [
                "mvn",
                "-Dspotless.check.skip=true",
                "-Dspotless.apply.skip=true",
                "-Dcargo.jvmargs=-Djava.security.egd=file:/dev/./urandom",
                "cargo:run",
                "-Pdeploy",
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,   # new process group so we can kill the tree
        )

    with open(APP_PID_FILE, "w") as pf:
        pf.write(str(proc.pid))

    log(f"Cargo started (PID {proc.pid}) — log at {APP_LOG}")
    return proc


def wait_for_app(timeout: int = STARTUP_TIMEOUT_SEC) -> bool:
    """Poll the app URL until it responds or timeout expires."""
    log(f"Waiting up to {timeout}s for app at {APP_URL}…")
    deadline = time.time() + timeout

    # Disable SSL verification for self-signed cert
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(APP_URL, context=ctx, timeout=5) as resp:
                if resp.status in (200, 302, 401, 403):
                    log(f"App is ready (HTTP {resp.status}).")
                    return True
        except Exception:
            pass
        elapsed = int(timeout - (deadline - time.time()))
        log(f"  … {elapsed}s elapsed, retrying in {POLL_INTERVAL_SEC}s")
        time.sleep(POLL_INTERVAL_SEC)

    log("ERROR: App did not start in time.")
    return False


def stop_app(proc: subprocess.Popen):
    """Kill the Cargo/Tomcat process tree."""
    log(f"Stopping Cargo (PID {proc.pid})…")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=30)
    except Exception as e:
        log(f"  Warning during stop: {e}")
    # Belt-and-suspenders: free the port
    subprocess.run(["fuser", "-k", f"{APP_PORT}/tcp"], capture_output=True)
    log("Cargo stopped.")


def run_zap_scan() -> int:
    """
    Run ZAP baseline scan via Docker.
    -I  = don't fail the container on alerts (we handle exit codes ourselves)
    Returns the Docker exit code (0-5 for ZAP baseline).
    """
    log("Starting ZAP baseline scan (Docker)…")
    result = run([
        "docker", "run", "--rm",
        "--network", "host",
        "-v", f"{ZAP_WORK_DIR}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t", APP_URL,
        "-J", ZAP_JSON_OUT,
        "-r", ZAP_HTML_OUT,
        "--auto",
        # Accept self-signed TLS cert
        "-z", "sslAcceptAll=true",
        "-I",           # ignore alerts for exit-code purposes (we parse ourselves)
    ])
    log(f"ZAP Docker exit code: {result.returncode}")
    return result.returncode


def parse_zap_report() -> list:
    """
    Parse ZAP JSON report and return a normalised list of findings.
    ZAP risk levels: 3=High, 2=Medium, 1=Low, 0=Informational
    """
    if not os.path.exists(ZAP_JSON_OUT):
        log(f"WARNING: ZAP JSON report not found at {ZAP_JSON_OUT}")
        return []

    with open(ZAP_JSON_OUT) as f:
        report = json.load(f)

    findings = []
    risk_labels = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFORMATIONAL"}

    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            if risk == 0:
                continue   # skip informational

            for instance in alert.get("instances", [{"uri": site.get("@name", "?"), "method": "?"}]):
                findings.append({
                    "tool":        "owasp-zap",
                    "alert":       alert.get("alert", "Unknown"),
                    "risk":        risk_labels.get(risk, str(risk)),
                    "riskcode":    risk,
                    "confidence":  alert.get("confidence", "?"),
                    "url":         instance.get("uri", "?"),
                    "method":      instance.get("method", "?"),
                    "param":       instance.get("param", ""),
                    "cwe":         alert.get("cweid", "?"),
                    "description": alert.get("desc", "")[:200],
                    "solution":    alert.get("solution", "")[:200],
                    "reference":   alert.get("reference", "")[:100],
                })

    return findings


def print_summary(findings: list):
    from collections import Counter
    counts = Counter(f["risk"] for f in findings)
    print("\n" + "=" * 60)
    print("  OWASP ZAP SCAN SUMMARY")
    print("=" * 60)
    for risk in ("HIGH", "MEDIUM", "LOW"):
        print(f"  {risk:12s}: {counts.get(risk, 0)}")
    print(f"  {'TOTAL':12s}: {len(findings)}")
    print("=" * 60)

    if findings:
        print("\nTop findings:")
        seen = set()
        for f in sorted(findings, key=lambda x: -x["riskcode"]):
            key = (f["alert"], f["risk"])
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{f['risk']:6s}] CWE-{f['cwe']} — {f['alert']}")
            print(f"           URL: {f['url']}")
    print()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("  OWASP ZAP DAST SCAN — Benchmark Pipeline")
    log("=" * 60)

    # 1. Build WAR
    if not build_war():
        sys.exit(1)

    # 2. Start app
    cargo_proc = start_app()

    try:
        # 3. Wait for app to be reachable
        if not wait_for_app():
            log("ERROR: App failed to start. Aborting ZAP scan.")
            stop_app(cargo_proc)
            sys.exit(1)

        # 4. Run ZAP scan
        zap_exit = run_zap_scan()
        log(f"ZAP scan complete (exit {zap_exit})")

    finally:
        # 5. Always stop the app
        stop_app(cargo_proc)

    # 6. Parse & save results
    findings = parse_zap_report()
    with open(ZAP_RESULTS, "w") as f:
        json.dump(findings, f, indent=2)
    log(f"Saved {len(findings)} findings to {ZAP_RESULTS}")

    # 7. Print summary
    print_summary(findings)

    high_count = sum(1 for f in findings if f["riskcode"] == 3)
    if high_count > 0:
        log(f"⚠  {high_count} HIGH-risk ZAP findings — review zap_report.html")
    else:
        log("✅  No HIGH-risk ZAP findings.")

    # Exit 0 always — let Jenkins decide pass/fail from the report
    sys.exit(0)


if __name__ == "__main__":
    main()
