import os
import time
import socket
import threading

os.system("")  # Enables ANSI colors in Windows CMD

def get_local_ip():
    """Finds your active Wi-Fi or Ethernet IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip, port = s.getsockname()
        return ip
    finally:
        s.close()

def send_syn(target_ip, port):
    """Triggers the Windows OS TCP/IP stack to send a real TCP SYN packet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect_ex((target_ip, port))
    except Exception:
        pass
    finally:
        s.close()

def run_syn_scan():
    local_ip = get_local_ip()
    a, b, c, d = local_ip.split(".")
    gateway_ip = f"{a}.{b}.{c}.1"

    print(f"\033[96m[*] Local IP: {local_ip} | Scanning Gateway: {gateway_ip}\033[0m")
    print("[*] Launching 30-port rapid TCP SYN scan (ports 20 to 49)...")

    threads = []
    for port in range(20, 50):
        t = threading.Thread(target=send_syn, args=(gateway_ip, port))
        threads.append(t)
        t.start()
        print(f"    -> Initiated SYN handshake on {gateway_ip}:{port}")
        time.sleep(0.03)

    for t in threads:
        t.join()

    print("\n\033[92m[*] Scan complete! Check your main.py console and ids_alerts.log.\033[0m")

if __name__ == "__main__":
    run_syn_scan()
