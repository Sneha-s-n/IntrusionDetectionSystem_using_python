import os
import sys
import json
import time
import socket
import ctypes
import logging
import subprocess
from collections import defaultdict
import numpy as np

from sklearn.ensemble import IsolationForest
from scapy.all import sniff, conf, IFACES
from scapy.layers.inet import IP, TCP


os.system("")  # Enables ANSI colors in Windows CMD

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "ids_alerts.log")
BLOCKED_PATH = os.path.join(BASE_DIR, "blocked_ips.json")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.WARNING,
    format="%(asctime)s - [ALERT] - %(message)s",
    force=True
)

def get_own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip, port = s.getsockname()
        return ip
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def ensure_demo_port_open():
    """Allows incoming TCP on port 5000 so Windows Firewall doesn't drop Kali's packets before Scapy sees them."""
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow_IPS_Demo_5000"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule", "name=Allow_IPS_Demo_5000", "dir=in", "action=allow", "protocol=TCP", "localport=5000"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

class HybridIPS:
    def __init__(self):
        self.own_ip = get_own_ip()
        self.syn_counts = defaultdict(list)
        self.packet_features = []
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False
        self.training_threshold = 50  # Fast 50-packet baseline
        self.safe_ips = {"127.0.0.1", "0.0.0.0", self.own_ip}
        self.blocked_ips = self.load_blocked_ips()

    def load_blocked_ips(self):
        if os.path.exists(BLOCKED_PATH):
            try:
                with open(BLOCKED_PATH, "r", encoding="utf-8") as f:
                    return set(json.load(f))
            except Exception:
                return set()
        return set()

    def save_blocked_ips(self):
        with open(BLOCKED_PATH, "w", encoding="utf-8") as f:
            json.dump(sorted(list(self.blocked_ips)), f, indent=2)

    def block_ip(self, ip):
        """Creates a Windows Firewall rule to block malicious IPs."""
        self.blocked_ips = self.load_blocked_ips()
        if ip in self.safe_ips or ip in self.blocked_ips:
            return

        rule_name = f"IDS_BLOCK_{ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.blocked_ips.add(ip)
        self.save_blocked_ips()

        msg = f"FIREWALL ACTION: Automatically blocked malicious IP {ip}"
        print(f"\033[95m{msg}\033[0m")
        logging.warning(msg)

    def extract_features(self, packet):
        pkt_len = len(packet)
        ttl = packet[IP].ttl
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = int(packet[TCP].flags)
        return [pkt_len, ttl, sport, dport, flags]

    def check_signatures(self, packet):
        src_ip = packet[IP].src
        flags = str(packet[TCP].flags)

        if "S" in flags and "A" not in flags:
            now = time.time()
            self.syn_counts[src_ip].append(now)
            self.syn_counts[src_ip] = [t for t in self.syn_counts[src_ip] if now - t <= 10]

            if len(self.syn_counts[src_ip]) > 15:
                alert_msg = f"Potential SYN Scan/Flood detected from {src_ip} ({len(self.syn_counts[src_ip])} SYNs in 10s)"
                print(f"\033[91m{alert_msg}\033[0m")
                logging.warning(alert_msg)
                self.block_ip(src_ip)
                self.syn_counts[src_ip].clear()

    def check_anomalies(self, packet, features):
        if not self.is_trained:
            self.packet_features.append(features)
            if len(self.packet_features) >= self.training_threshold:
                print("[*] Baseline traffic captured. Training anomaly detection model...")
                self.model.fit(np.array(self.packet_features))
                self.is_trained = True
                print("[*] Model trained. Active IPS monitoring started.")
            return

        prediction = self.model.predict([features])
        if prediction == -1:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            pkt_size, ttl, sport, dport, pkt_flags = features
            alert_msg = f"Anomalous TCP traffic from {src_ip} targeting port {dst_port} (Size: {pkt_size} bytes, Flags: {pkt_flags})"
            print(f"\033[93m{alert_msg}\033[0m")
            logging.warning(alert_msg)

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            if src_ip not in self.safe_ips:
                print(f"\033[96m[INCOMING] {src_ip} -> Port {packet[TCP].dport} | Flags: {packet[TCP].flags}\033[0m")
            self.check_signatures(packet)
            features = self.extract_features(packet)
            self.check_anomalies(packet, features)

    def start(self):
        ensure_demo_port_open()
        target_iface = None
        for iface in IFACES.values():
            if getattr(iface, "ip", None) == self.own_ip:
                target_iface = iface
                break

        print(f"[*] Binding IPS listener to adapter: {target_iface.name if target_iface else 'Default'} ({self.own_ip})")
        print(f"[*] Protected Safe IPs (Never Blocked): {self.safe_ips}")
        print(f"[*] Starting Hybrid IPS... Collecting {self.training_threshold} packets for baseline.")
        print("[*] Press Ctrl+C to stop.")

        l3_sock = conf.L3socket(iface=target_iface) if target_iface else conf.L3socket()
        sniff(
            opened_socket=l3_sock,
            prn=self.process_packet,
            store=False
        )

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if __name__ == "__main__":
    if not is_admin():
        cmd = f'/k ""{sys.executable}" "{__file__}""'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", cmd, None, 1)
        sys.exit(0)

    ips = HybridIPS()
    ips.start()
