#!/usr/bin/env python3
"""
zap_full_report.py — Standalone OWASP ZAP scan of the entire Benchmark app.

Usage:
    python3 zap_full_report.py [--no-start] [--spider-mins N]

Options:
    --no-start      Skip starting the app (use if already running on port 8443)
    --spider-mins N ZAP spider time in minutes (default: 5)

Output (all saved to reports/zap/<timestamp>/):
    zap_report.html     Full interactive ZAP HTML report
    zap_report.json     Raw ZAP JSON output
    zap_alerts.csv      Every alert as a CSV row (for ML/analysis)
    summary.md          Human-readable markdown summary
"""

import argparse
import csv
import json
import os
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import socket

# ── Config ───────────────────────────────────────────────────────────────────
# NOTE: effective values are set after build_war() below (lines ~100-107)
# These placeholders are overridden once CARGO_*_PORT constants are defined.
_APP_PORT_PLACEHOLDER = 8443
APP_LOG           = "/tmp/benchmark_cargo.log"
ZAP_IMAGE         = "ghcr.io/zaproxy/zaproxy:stable"
POLL_INTERVAL     = 5

REPO_ROOT         = Path(__file__).resolve().parent.parent   # sem6-project/
REPORTS_BASE      = REPO_ROOT / "reports" / "zap"
RISK_LABEL        = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFORMATIONAL"}
RISK_EMOJI        = {3: "🔴", 2: "🟡", 1: "🔵", 0: "⚪"}

# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def banner(title: str):
    line = "=" * 60
    print(f"\n{line}")
    print(f"  {title}")
    print(f"{line}\n")


def run(cmd, **kwargs) -> subprocess.CompletedProcess:
    log(f"$ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, **kwargs)

# ── App management ────────────────────────────────────────────────────────────

def is_app_running() -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(APP_URL, context=ctx, timeout=5) as r:
            return r.status in (200, 302, 401, 403)
    except Exception:
        return False


def free_ports(*ports):
    """Kill any process holding the given TCP ports."""
    for port in ports:
        r = subprocess.run(["fuser", "-k", f"{port}/tcp"],
                          capture_output=True)
        if r.returncode == 0:
            log(f"  Freed port {port}")
        time.sleep(1)  # give OS time to release


def build_war():
    banner("Building WAR")
    r = run([
        "mvn", "-DskipTests",
        "-Dspotless.check.skip=true",
        "-Dspotless.apply.skip=true",
        "clean", "package",
    ])
    if r.returncode != 0:
        log("ERROR: WAR build failed — aborting.")
        sys.exit(1)
    log("WAR build OK.")


CARGO_SERVLET_PORT = 8443   # hardcoded in target/tomcat9x/conf/server.xml
CARGO_RMI_PORT     = 8205   # hardcoded in target/tomcat9x/conf/server.xml
CARGO_AJP_PORT     = 8009   # hardcoded in target/tomcat9x/conf/server.xml

APP_PORT = CARGO_SERVLET_PORT
APP_URL  = f"https://localhost:{APP_PORT}/benchmark/Index.html"
# Spider seed — ZAP will follow links from here to all test servlets

STARTUP_TIMEOUT = 300   # 5 min — WAR with 2770 servlets takes time to deploy

def start_app() -> subprocess.Popen:
    banner("Starting Benchmark App (Cargo/Tomcat 9)")
    free_ports(CARGO_SERVLET_PORT, CARGO_RMI_PORT, CARGO_AJP_PORT)
    time.sleep(2)  # let OS fully release ports
    run(["mvn", "-q",
         "-Dspotless.check.skip=true", "-Dspotless.apply.skip=true",
         "initialize"])

    with open(APP_LOG, "w") as lf:
        proc = subprocess.Popen(
            [
                "mvn",
                "-Dspotless.check.skip=true",
                "-Dspotless.apply.skip=true",
                "-Dcargo.jvmargs=-Djava.security.egd=file:/dev/./urandom",
                "cargo:run", "-Pdeploy",
            ],
            stdout=lf, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
    log(f"Cargo started (PID {proc.pid})  — tail {APP_LOG} to watch")
    return proc


def wait_for_app(timeout: int = STARTUP_TIMEOUT) -> bool:
    """Two-stage readiness check:
    1. TCP connect to the port (fast — detects when Tomcat starts listening)
    2. HTTPS request (confirms Tomcat is serving — any HTTP response means ready)

    IMPORTANT: urllib.request.urlopen raises HTTPError for 4xx/5xx responses
    so we must catch it explicitly. Any HTTPError still means Tomcat IS up.
    """
    import urllib.error

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    start = time.time()
    deadline = start + timeout
    log(f"Waiting up to {timeout}s for {APP_URL} …")
    while time.time() < deadline:
        elapsed = int(time.time() - start)

        # Stage 1: raw TCP connect
        try:
            with socket.create_connection(("localhost", APP_PORT), timeout=3):
                pass  # port is open
        except (ConnectionRefusedError, OSError):
            log(f"  [{elapsed:3d}s] port {APP_PORT} not open yet — retrying in {POLL_INTERVAL}s")
            time.sleep(POLL_INTERVAL)
            continue

        # Stage 2: HTTPS — any response (including 4xx) means the app is UP
        try:
            with urllib.request.urlopen(APP_URL, context=ctx, timeout=10) as r:
                log(f"✅ App is ready after {elapsed}s (HTTP {r.status})")
                return True
        except urllib.error.HTTPError as e:
            # 4xx/5xx from Tomcat → app IS running, just returning an error page
            log(f"✅ App is ready after {elapsed}s (HTTP {e.code} from Tomcat)")
            return True
        except Exception as e:
            log(f"  [{elapsed:3d}s] TLS/HTTP not ready yet ({type(e).__name__}: {e}) — retrying in {POLL_INTERVAL}s")
        time.sleep(POLL_INTERVAL)

    return False


def stop_app(proc: subprocess.Popen):
    banner("Stopping Benchmark App")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=30)
    except Exception as e:
        log(f"  (warning) {e}")
    free_ports(CARGO_SERVLET_PORT, CARGO_RMI_PORT, CARGO_AJP_PORT)
    log("App stopped.")

# ── ZAP scan ─────────────────────────────────────────────────────────────────

def pull_zap_image():
    log(f"Pulling ZAP image: {ZAP_IMAGE}")
    run(["docker", "pull", ZAP_IMAGE])


def run_zap(out_dir: Path, spider_mins: int) -> int:
    banner(f"Running ZAP Baseline Scan  (spider: {spider_mins} min)")
    log(f"Target : {APP_URL}")
    log(f"Reports: {out_dir}")

    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-v", f"{out_dir}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t", APP_URL,
        "-J", "zap_report.json",     # saved inside /zap/wrk = out_dir
        "-r", "zap_report.html",
        "-m", str(spider_mins),      # minutes for traditional spider
        "-z", "-config ssl.insecure=true",   # accept self-signed TLS cert
        "-I",                        # don't fail container on alerts
    ]
    r = run(cmd)
    log(f"ZAP Docker exit code: {r.returncode}")
    return r.returncode

# ── Report parsing ────────────────────────────────────────────────────────────

def parse_report(out_dir: Path) -> list[dict]:
    json_path = out_dir / "zap_report.json"
    if not json_path.exists():
        log("WARNING: zap_report.json not found — ZAP may not have written output.")
        return []

    with open(json_path) as f:
        data = json.load(f)

    alerts = []
    for site in data.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            risk     = int(alert.get("riskcode", 0))
            conf     = int(alert.get("confidence", 0))
            conf_lbl = {3: "High", 2: "Medium", 1: "Low", 0: "False Positive"}.get(conf, str(conf))

            for inst in alert.get("instances", [{}]):
                alerts.append({
                    "alert":       alert.get("alert", ""),
                    "risk":        RISK_LABEL.get(risk, str(risk)),
                    "riskcode":    risk,
                    "confidence":  conf_lbl,
                    "cwe":         alert.get("cweid", ""),
                    "wasc":        alert.get("wascid", ""),
                    "url":         inst.get("uri", site_name),
                    "method":      inst.get("method", ""),
                    "param":       inst.get("param", ""),
                    "evidence":    inst.get("evidence", "")[:120],
                    "description": alert.get("desc", "")[:300],
                    "solution":    alert.get("solution", "")[:300],
                    "reference":   alert.get("reference", "")[:150],
                })

    return sorted(alerts, key=lambda x: -x["riskcode"])


def write_csv(alerts: list[dict], out_dir: Path):
    csv_path = out_dir / "zap_alerts.csv"
    if not alerts:
        csv_path.write_text("(no alerts)\n")
        return
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows(alerts)
    log(f"CSV saved: {csv_path}")


def write_markdown(alerts: list[dict], out_dir: Path, scan_ts: str, zap_exit: int):
    from collections import Counter, defaultdict
    counts = Counter(a["risk"] for a in alerts)
    by_alert = defaultdict(list)
    for a in alerts:
        by_alert[(a["alert"], a["risk"], a["cwe"])].append(a)

    md = []
    md.append(f"# OWASP ZAP Scan Report\n")
    md.append(f"**Target:** `{APP_URL}`  ")
    md.append(f"**Scan date:** {scan_ts}  ")
    md.append(f"**ZAP exit code:** {zap_exit}\n")

    md.append("## Summary\n")
    md.append("| Risk | Count |")
    md.append("|------|------:|")
    for risk in ("HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        emoji = RISK_EMOJI.get({"HIGH":3,"MEDIUM":2,"LOW":1,"INFORMATIONAL":0}[risk], "")
        md.append(f"| {emoji} {risk} | {counts.get(risk, 0)} |")
    md.append(f"| **TOTAL** | **{len(alerts)}** |\n")

    md.append("## Findings\n")
    if not alerts:
        md.append("_No alerts found._\n")
    else:
        for (name, risk, cwe), instances in sorted(
            by_alert.items(), key=lambda x: -{"HIGH":3,"MEDIUM":2,"LOW":1,"INFORMATIONAL":0}.get(x[0][1],0)
        ):
            emoji = RISK_EMOJI.get({"HIGH":3,"MEDIUM":2,"LOW":1,"INFORMATIONAL":0}.get(risk,0), "")
            md.append(f"### {emoji} {name}")
            md.append(f"- **Risk:** {risk}  ")
            md.append(f"- **CWE:** {cwe}  ")
            md.append(f"- **Instances:** {len(instances)}  ")
            # Show first instance
            inst = instances[0]
            md.append(f"- **Description:** {inst['description'].strip()}  ")
            md.append(f"- **Solution:** {inst['solution'].strip()}  ")
            md.append("\n**Affected URLs (up to 5):**\n")
            for i in instances[:5]:
                param = f" (`{i['param']}`)" if i["param"] else ""
                md.append(f"- `{i['method']} {i['url']}`{param}")
            if len(instances) > 5:
                md.append(f"- _…and {len(instances)-5} more_")
            md.append("")

    md.append("\n---\n")
    md.append(f"_Generated by zap_full_report.py — {scan_ts}_\n")

    summary_path = out_dir / "summary.md"
    summary_path.write_text("\n".join(md))
    log(f"Markdown saved: {summary_path}")


def print_console_summary(alerts: list[dict]):
    from collections import Counter
    counts = Counter(a["risk"] for a in alerts)
    banner("ZAP SCAN COMPLETE — RESULTS")
    print(f"  {'RISK':<14} {'COUNT':>6}")
    print(f"  {'-'*22}")
    for risk in ("HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        emoji = RISK_EMOJI.get({"HIGH":3,"MEDIUM":2,"LOW":1,"INFORMATIONAL":0}[risk], "")
        print(f"  {emoji} {risk:<12} {counts.get(risk, 0):>6}")
    print(f"  {'-'*22}")
    print(f"  {'TOTAL':<14} {len(alerts):>6}\n")

    if alerts:
        print("Top findings (unique alert types):\n")
        seen = set()
        for a in alerts:
            if a["alert"] in seen:
                continue
            seen.add(a["alert"])
            emoji = RISK_EMOJI.get(a["riskcode"], "")
            cwe   = f"CWE-{a['cwe']}" if a["cwe"] else ""
            print(f"  {emoji} [{a['risk']:6}] {cwe:10} {a['alert']}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Run a full OWASP ZAP scan of the Benchmark app")
    parser.add_argument("--no-start",    action="store_true",
                        help="Skip starting the app (use if already running on port 8443)")
    parser.add_argument("--spider-mins", type=int, default=5,
                        help="ZAP spider time in minutes (default: 5)")
    args = parser.parse_args()

    scan_ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = REPORTS_BASE / scan_ts
    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"Report directory: {out_dir}")

    cargo_proc = None

    # ── 1. Pull ZAP image early while app starts ──
    pull_zap_image()

    # ── 2. Start app (unless --no-start) ──
    if args.no_start:
        if not is_app_running():
            log("ERROR: --no-start given but app is not reachable on port 8443.")
            sys.exit(1)
        log("Using already-running app.")
    else:
        if is_app_running():
            log("App already running on port 8443 — skipping startup.")
        else:
            build_war()
            cargo_proc = start_app()
            if not wait_for_app():
                log("ERROR: App did not become ready in time.")
                if cargo_proc:
                    stop_app(cargo_proc)
                sys.exit(1)

    # ── 3. ZAP scan ──
    try:
        zap_exit = run_zap(out_dir, args.spider_mins)
    finally:
        if cargo_proc:
            stop_app(cargo_proc)

    # ── 4. Parse & write reports ──
    banner("Generating Reports")
    alerts = parse_report(out_dir)
    write_csv(alerts, out_dir)
    write_markdown(alerts, out_dir, scan_ts, zap_exit)

    # ── 5. Print console summary ──
    print_console_summary(alerts)

    print(f"\n📁 All reports saved to:\n   {out_dir}\n")
    print(f"   zap_report.html  — open in browser for full interactive report")
    print(f"   summary.md       — readable markdown summary")
    print(f"   zap_alerts.csv   — all alerts as CSV (for analysis/ML)")
    print(f"   zap_report.json  — raw ZAP JSON\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
