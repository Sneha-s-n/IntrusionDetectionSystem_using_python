import os
import io
import re
import csv
import json
import subprocess
from flask import Flask, render_template, jsonify, redirect, url_for, request, Response

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "ids_alerts.log")
BLOCKED_PATH = os.path.join(BASE_DIR, "blocked_ips.json")

def load_blocked():
    if os.path.exists(BLOCKED_PATH):
        try:
            with open(BLOCKED_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_blocked(ip_list):
    with open(BLOCKED_PATH, "w", encoding="utf-8") as f:
        json.dump(sorted(list(set(ip_list))), f, indent=2)

def parse_logs():
    alerts = []
    syn_scans = 0
    anomalies = 0
    attacker_stats = {}

    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line in reversed(lines):
            if " - [ALERT] - " in line:
                timestamp, msg = line.strip().split(" - [ALERT] - ", 1)

                # Extract IP address from alert message
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", msg)
                source_ip = ip_match.group(1) if ip_match else "Unknown"

                # Extract target port if present
                port_match = re.search(r"port (\d+)", msg)
                target_port = port_match.group(1) if port_match else "Multiple / N/A"

                if "FIREWALL ACTION" in msg:
                    severity, engine = "BLOCKED", "Windows Firewall IPS"
                    description = "Active containment executed via netsh advfirewall. Inbound traffic from this attacker IP is now dropped at the OS firewall level."
                    recommendation = "Keep IP blocked until forensic investigation completes, or click Unblock IP if this was an authorized penetration test."
                elif "SYN Scan/Flood" in msg:
                    syn_scans += 1
                    severity, engine = "CRITICAL", "Signature Engine"
                    description = "High-rate TCP SYN packets detected without completing the 3-way handshake. Strongly indicates Nmap stealth scanning or a SYN flood Denial-of-Service attempt."
                    recommendation = "Immediate IP block applied automatically. Verify source host on local subnet."
                    if source_ip != "Unknown":
                        attacker_stats[source_ip] = attacker_stats.get(source_ip, 0) + 1
                else:
                    anomalies += 1
                    severity, engine = "WARNING", "Isolation Forest ML"
                    description = "Unsupervised Isolation Forest model flagged packet size, TTL, port, or TCP flag combination as a statistical outlier compared to baseline traffic."
                    recommendation = "Monitor host behavior. If traffic originates from an external IP on unusual ports, consider manual firewall blocking."

                alerts.append({
                    "timestamp": timestamp,
                    "severity": severity,
                    "engine": engine,
                    "source_ip": source_ip,
                    "target_port": target_port,
                    "message": msg,
                    "description": description,
                    "recommendation": recommendation
                })

    # Always keep all CRITICAL and BLOCKED events so they never get pushed off by ML warnings
    critical_and_blocked = [a for a in alerts if a["severity"] in ("CRITICAL", "BLOCKED")]
    warnings = [a for a in alerts if a["severity"] == "WARNING"][:50]
    combined_alerts = critical_and_blocked + warnings
    combined_alerts.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "total": len(alerts),
        "syn_scans": syn_scans,
        "anomalies": anomalies,
        "blocked_ips": load_blocked(),
        "attackers": [{"ip": k, "count": v} for k, v in attacker_stats.items()],
        "alerts": combined_alerts
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/data")
def api_data():
    return jsonify(parse_logs())

@app.route("/block", methods=["POST"])
def manual_block():
    ip = request.form.get("ip", "").strip()
    if ip and ip != "127.0.0.1":
        rule_name = f"IDS_BLOCK_{ip}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        blocked = load_blocked()
        blocked.append(ip)
        save_blocked(blocked)
    return redirect(url_for("index"))

@app.route("/unblock", methods=["POST"])
def unblock_ip():
    ip = request.form.get("ip", "").strip()
    if ip:
        rule_name = f"IDS_BLOCK_{ip}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        blocked = [item for item in load_blocked() if item != ip]
        save_blocked(blocked)
    return redirect(url_for("index"))

@app.route("/export")
def export_csv():
    data = parse_logs()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Severity", "Source/Attacker IP", "Target Port", "Detection Engine", "Alert Details"])
    for a in data["alerts"]:
        writer.writerow([a["timestamp"], a["severity"], a["source_ip"], a["target_port"], a["engine"], a["message"]])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=ids_security_report.csv"}
    )

@app.route("/clear", methods=["POST"])
def clear_logs():
    if os.path.exists(LOG_PATH):
        open(LOG_PATH, "w").close()
    return redirect(url_for("index"))

if __name__ == "__main__":
    print("[*] Starting IPS Web Dashboard at http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
