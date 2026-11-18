🛡️ Hybrid Intrusion Detection System (IDS) & Live SOC Dashboard

A real-time network security and active threat containment application built in **Python**. This project upgrades a traditional passive Intrusion Detection System (IDS) into an active **Intrusion Prevention System (IPS)** by combining signature-based packet inspection, unsupervised machine learning anomaly detection, automated **Windows Defender Firewall** blocking, and a live **Flask Security Operations Center (SOC)** web dashboard.

---
🚀 Key Features

* **Dual-Engine Hybrid Detection:**
  * **Signature-Based Engine:** Tracks incoming TCP `SYN` packets per source IP within a sliding 10-second window to detect stealth port scans (e.g., Nmap `-sS` / `-sT`) and SYN flood attacks.
  * **Machine Learning Anomaly Engine:** Extracts 5 packet-level features (`packet length`, `TTL`, `source port`, `destination port`, and `TCP flags`) to train an unsupervised **Isolation Forest** model (`scikit-learn`) on live baseline traffic, flagging statistical outliers in real time.
* **Automated Intrusion Prevention (IPS):**
  * Automatically executes native Windows `netsh advfirewall` commands to drop inbound traffic from confirmed attacking IP addresses within seconds.
  * Built-in **Safe IP Whitelist** (`127.0.0.1`, `0.0.0.0`, and the host's local adapter IP) prevents accidental self-lockout.
* **Interactive SOC Web Dashboard:**
  * Live-updating statistics cards with severity filtering (`ALL`, `CRITICAL`, `WARNING`).
  * Clickable incident rows opening a **Threat Intelligence Modal** with raw telemetry, threat analysis, and mitigation guidance.
  * **Firewall Blocklist Manager** to manually block or unblock IPs with one click.
  * **CSV Security Report Export** for incident auditing and documentation.

---

## 🏗️ System Architecture

```text
[External Network Traffic / Kali Linux Attacker]
                       │
                       ▼
      ┌─────────────────────────────────┐
      │   Packet Capture Engine (Scapy) │
      │   Layer-3 Socket Interface Bind │
      └────────────────┬────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
┌───────────────────┐         ┌───────────────────┐
│ Signature Engine  │         │  Anomaly Engine   │
│  (SYN Scan/Flood  │         │ (Isolation Forest │
│  Rate Threshold)  │         │   Unsupervised)   │
└─────────┬─────────┘         └─────────┬─────────┘
          │                             │
          └──────────────┬──────────────┘
                         ▼
      ┌─────────────────────────────────┐
      │   Automated Response & Logging  │
      │ • Windows Firewall Rule (netsh) │
      │ • ids_alerts.log & blocked.json │
      └────────────────┬────────────────┘
                       │
                       ▼
      ┌─────────────────────────────────┐
      │     Flask Web SOC Dashboard     │
      │  Live Metrics, Unblock & CSV    │
      └─────────────────────────────────┘
```

---

## 📂 Project Structure

```text
IntrusionDetectionSystem/
├── main.py                # Core Hybrid IPS engine (Scapy + Isolation Forest + Firewall blocker)
├── dashboard.py           # Flask backend API, CSV report generator & firewall controller
├── test_attack.py         # Multi-threaded TCP SYN scan simulator for local testing
├── templates/
│   └── index.html         # Interactive dark-mode SOC web dashboard & incident modal
├── ids_alerts.log         # Persistent timestamped alert & firewall action logs
├── blocked_ips.json       # Synchronized JSON store of active firewall block rules
└── README.md              # Project documentation
```

---

## ⚙️ Installation & Setup

### 1. Prerequisites
* **OS:** Windows 10 / 11 (Administrator privileges required for raw sockets and Windows Firewall rules)
* **Python:** Python 3.11+

### 2. Clone the Repository & Install Dependencies
```bash
git clone https://github.com/Sneha-s-n/IntrusionDetectionSystem_using_python.git
cd IntrusionDetectionSystem_using_python
pip install scapy scikit-learn numpy flask
```

---

## 🖥️ Usage & Live Demo Flow

### Step 1: Start the IPS Engine (`main.py`)
Run `main.py` (it will automatically request Administrator elevation on Windows):
```bash
python main.py
```
Browse 1–2 webpages so the engine captures its initial 50 baseline packets and prints:
`[*] Model trained. Active IPS monitoring started.`

### Step 2: Launch the SOC Web Dashboard (`dashboard.py`)
In a second terminal (run as Administrator to enable dashboard Unblock buttons):
```bash
python dashboard.py
```
Open **`http://127.0.0.1:5000`** in your web browser.

### Step 3: Simulate an Attack (Kali Linux or Local Script)
* **From a Kali Linux machine on the same network:**
  ```bash
  nmap <WINDOWS_IP> 
  ```
* **Or locally using the included simulator:**
  ```bash
  python test_attack.py
  ```
Within seconds, the dashboard will log the **CRITICAL** SYN scan alert, display the attacker's IP in the **Windows Firewall Blocklist**, and block further packets from the attacker.

---


