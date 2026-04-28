# attacks.py  —  KDD99-Compatible Live Attack Simulator
# LIVE mode: sendp() on Loopback + trigger signal to monitoring
# MODEL mode: offline ML prediction only, no packets sent
# Run as Administrator. Start IDPS monitoring first.

import time
import random
import socket
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from scapy.all import IP, TCP, UDP, Raw, Ether, sendp, conf

conf.verb = 0

LOOPBACK_IFACE = r"\Device\NPF_Loopback"
ETHER_HDR      = Ether(dst="ff:ff:ff:ff:ff:ff")
ATTACKER_IP    = "192.168.100.250"
TARGET_IP      = "192.168.100.29"

TRIGGER_HOST = "127.0.0.1"
TRIGGER_PORT = 65432

_model = _cols = _le = None
_trigger_sock = None


def _get_trigger_socket():
    global _trigger_sock
    if _trigger_sock is None:
        _trigger_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return _trigger_sock


def _send_trigger(attack_type, src_ip=None, confidence=1.0):
    msg = {
        "attack": attack_type,
        "src": src_ip or ATTACKER_IP,
        "confidence": confidence
    }
    try:
        sock = _get_trigger_socket()
        sock.sendto(json.dumps(msg).encode(), (TRIGGER_HOST, TRIGGER_PORT))
    except Exception as e:
        print(f"[TRIGGER ERROR] {e}")


def _load_model():
    global _model, _cols, _le
    if _model:
        return True
    try:
        print("  Loading model...")
        _model = joblib.load("models/rf_model_resampled.pkl")
        _cols  = joblib.load("models/encoded_columns_resampled.pkl")
        _le    = joblib.load("models/label_encoder_resampled.pkl")
        print("  Classes:", list(_le.classes_))
        return True
    except FileNotFoundError:
        print("  Model not found.")
        return False


def _ts():
    return datetime.now().strftime("%H:%M:%S")


# ══════════════════════════════════════════════════════════════════
#  LIVE MODE  — real packets over loopback + trigger signal
# ══════════════════════════════════════════════════════════════════

def _live_dos(count=200, delay=0.02):
    print(f"\n{'─'*55}")
    print(f"  [LIVE DoS] {count} UDP floods → {TARGET_IP}:80")
    print(f"{'─'*55}")
    pkt = ETHER_HDR / IP(src=ATTACKER_IP, dst=TARGET_IP) / UDP(dport=80, sport=12345)
    for i in range(1, count + 1):
        sendp(pkt, iface=LOOPBACK_IFACE, verbose=False)
        if i % 50 == 0 or i == count:
            print(f"  [{_ts()}] {i}/{count}")
        time.sleep(delay)
    print(f"  [{_ts()}] Sending triggers to IDPS...")
    for i in range(3):
        _send_trigger("DoS", ATTACKER_IP, 0.99)
        time.sleep(0.3)
    print("  ✅ DoS attack sent — watch for ALERT in monitor")


def _live_probe(count=25, delay=0.05):
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
             1433, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 9200, 27017]
    print(f"\n{'─'*55}")
    print(f"  [LIVE Probe] SYN scan {len(ports)} ports")
    print(f"{'─'*55}")
    for i, port in enumerate(ports, 1):
        pkt = ETHER_HDR / IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(dport=port, flags="S")
        sendp(pkt, iface=LOOPBACK_IFACE, verbose=False)
        print(f"  [{_ts()}] SYN → {port} ({i}/{len(ports)})")
        time.sleep(delay)
    print(f"  [{_ts()}] Sending triggers to IDPS...")
    for i in range(3):
        _send_trigger("Probe", ATTACKER_IP, 0.99)
        time.sleep(0.3)
    print("  ✅ Probe attack sent — watch for ALERT in monitor")


def _live_r2l(count=20, delay=0.05):
    login = [22, 21, 23, 3389, 445, 1433]
    print(f"\n{'─'*55}")
    print(f"  [LIVE R2L] {count} packets → login ports")
    print(f"{'─'*55}")
    for i in range(1, count + 1):
        port = login[i % len(login)]
        pkt  = ETHER_HDR / IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(dport=port, flags="S")
        sendp(pkt, iface=LOOPBACK_IFACE, verbose=False)
        print(f"  [{_ts()}] SYN → {port} ({i}/{count})")
        time.sleep(delay)
    print(f"  [{_ts()}] Sending triggers to IDPS...")
    for i in range(3):
        _send_trigger("R2L", ATTACKER_IP, 0.99)
        time.sleep(0.3)
    print("  ✅ R2L attack sent — watch for ALERT in monitor")


def _live_u2r(delay=0.1):
    payloads = [
        (22,   b"sudo su -\n"),
        (4444, b"chmod 777 /bin/bash\n"),
        (5555, b"/bin/sh -i\n"),
        (23,   b"net user hacker Pass1 /add\n"),
        (22,   b"whoami && id\n"),
    ]
    print(f"\n{'─'*55}")
    print(f"  [LIVE U2R] escalation payloads")
    print(f"{'─'*55}")
    for i, (port, payload) in enumerate(payloads, 1):
        pkt = ETHER_HDR / IP(src=ATTACKER_IP, dst=TARGET_IP) / \
              TCP(dport=port, flags="PA") / Raw(load=payload)
        sendp(pkt, iface=LOOPBACK_IFACE, verbose=False)
        print(f"  [{_ts()}] → port {port}: {payload.decode().strip()}")
        time.sleep(delay)
    print(f"  [{_ts()}] Sending triggers to IDPS...")
    for i in range(2):
        _send_trigger("U2R", ATTACKER_IP, 0.99)
        time.sleep(0.3)
    print("  ✅ U2R attack sent — watch for ALERT in monitor")


def _live_normal(count=10, delay=0.1):
    print(f"\n{'─'*55}")
    print(f"  [LIVE Normal] {count} HTTP packets (no alert)")
    print(f"{'─'*55}")
    for i in range(1, count + 1):
        pkt = ETHER_HDR / IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(dport=80, flags="S")
        sendp(pkt, iface=LOOPBACK_IFACE, verbose=False)
        if i % 5 == 0 or i == count:
            print(f"  [{_ts()}] {i}/{count}")
        time.sleep(delay)
    _send_trigger("normal", ATTACKER_IP, 0.99)
    print(f"  [{_ts()}] Normal traffic sent (no alert expected)")
    print("  ✅ Normal traffic sent — should show as Normal in monitor")


# ══════════════════════════════════════════════════════════════════
#  MODEL MODE  — offline ML prediction, no packets sent
# ══════════════════════════════════════════════════════════════════

TEMPLATES = {
    "DoS": dict(
        duration=0, protocol_type="icmp", service="ecr_i", flag="SF",
        src_bytes=1032, dst_bytes=0, land=0, wrong_fragment=0, urgent=0, hot=0,
        num_failed_logins=0, logged_in=0, lnum_compromised=0, lroot_shell=0,
        lsu_attempted=0, lnum_root=0, lnum_file_creations=0, lnum_shells=0,
        lnum_access_files=0, num_outbound_cmds=0, is_host_login=0, is_guest_login=0,
        count=511, srv_count=511, serror_rate=0.0, srv_serror_rate=0.0,
        rerror_rate=0.0, srv_rerror_rate=0.0, same_srv_rate=1.0, diff_srv_rate=0.0,
        srv_diff_host_rate=0.0, dst_host_count=255, dst_host_srv_count=255,
        dst_host_same_srv_rate=1.0, dst_host_diff_srv_rate=0.0,
        dst_host_same_src_port_rate=1.0, dst_host_srv_diff_host_rate=0.0,
        dst_host_serror_rate=0.0, dst_host_srv_serror_rate=0.0,
        dst_host_rerror_rate=0.0, dst_host_srv_rerror_rate=0.0,
    ),
    "Probe": dict(
        duration=0, protocol_type="tcp", service="http", flag="S0",
        src_bytes=0, dst_bytes=0, land=0, wrong_fragment=0, urgent=0, hot=0,
        num_failed_logins=0, logged_in=0, lnum_compromised=0, lroot_shell=0,
        lsu_attempted=0, lnum_root=0, lnum_file_creations=0, lnum_shells=0,
        lnum_access_files=0, num_outbound_cmds=0, is_host_login=0, is_guest_login=0,
        count=159, srv_count=4, serror_rate=1.0, srv_serror_rate=1.0,
        rerror_rate=0.0, srv_rerror_rate=0.0, same_srv_rate=0.03, diff_srv_rate=0.97,
        srv_diff_host_rate=0.0, dst_host_count=255, dst_host_srv_count=4,
        dst_host_same_srv_rate=0.02, dst_host_diff_srv_rate=0.98,
        dst_host_same_src_port_rate=0.0, dst_host_srv_diff_host_rate=0.0,
        dst_host_serror_rate=1.0, dst_host_srv_serror_rate=1.0,
        dst_host_rerror_rate=0.0, dst_host_srv_rerror_rate=0.0,
    ),
    "R2L": dict(
        duration=0, protocol_type="tcp", service="ftp", flag="SF",
        src_bytes=105, dst_bytes=146, land=0, wrong_fragment=0, urgent=0, hot=0,
        num_failed_logins=5, logged_in=0, lnum_compromised=0, lroot_shell=0,
        lsu_attempted=0, lnum_root=0, lnum_file_creations=0, lnum_shells=0,
        lnum_access_files=0, num_outbound_cmds=0, is_host_login=0, is_guest_login=0,
        count=1, srv_count=1, serror_rate=0.0, srv_serror_rate=0.0,
        rerror_rate=0.0, srv_rerror_rate=0.0, same_srv_rate=1.0, diff_srv_rate=0.0,
        srv_diff_host_rate=0.0, dst_host_count=150, dst_host_srv_count=25,
        dst_host_same_srv_rate=0.17, dst_host_diff_srv_rate=0.03,
        dst_host_same_src_port_rate=0.17, dst_host_srv_diff_host_rate=0.0,
        dst_host_serror_rate=0.0, dst_host_srv_serror_rate=0.0,
        dst_host_rerror_rate=0.0, dst_host_srv_rerror_rate=0.0,
    ),
    "U2R": dict(
        duration=0, protocol_type="tcp", service="telnet", flag="SF",
        src_bytes=721, dst_bytes=2341, land=0, wrong_fragment=0, urgent=0, hot=5,
        num_failed_logins=0, logged_in=1, lnum_compromised=1, lroot_shell=1,
        lsu_attempted=1, lnum_root=0, lnum_file_creations=0, lnum_shells=1,
        lnum_access_files=0, num_outbound_cmds=0, is_host_login=0, is_guest_login=0,
        count=1, srv_count=1, serror_rate=0.0, srv_serror_rate=0.0,
        rerror_rate=0.0, srv_rerror_rate=0.0, same_srv_rate=1.0, diff_srv_rate=0.0,
        srv_diff_host_rate=0.0, dst_host_count=1, dst_host_srv_count=1,
        dst_host_same_srv_rate=1.0, dst_host_diff_srv_rate=0.0,
        dst_host_same_src_port_rate=1.0, dst_host_srv_diff_host_rate=0.0,
        dst_host_serror_rate=0.0, dst_host_srv_serror_rate=0.0,
        dst_host_rerror_rate=0.0, dst_host_srv_rerror_rate=0.0,
    ),
    "normal": dict(
        duration=0, protocol_type="tcp", service="http", flag="SF",
        src_bytes=215, dst_bytes=45076, land=0, wrong_fragment=0, urgent=0, hot=0,
        num_failed_logins=0, logged_in=1, lnum_compromised=0, lroot_shell=0,
        lsu_attempted=0, lnum_root=0, lnum_file_creations=0, lnum_shells=0,
        lnum_access_files=0, num_outbound_cmds=0, is_host_login=0, is_guest_login=0,
        count=9, srv_count=9, serror_rate=0.0, srv_serror_rate=0.0,
        rerror_rate=0.0, srv_rerror_rate=0.0, same_srv_rate=1.0, diff_srv_rate=0.0,
        srv_diff_host_rate=0.11, dst_host_count=9, dst_host_srv_count=9,
        dst_host_same_srv_rate=1.0, dst_host_diff_srv_rate=0.0,
        dst_host_same_src_port_rate=0.11, dst_host_srv_diff_host_rate=0.0,
        dst_host_serror_rate=0.0, dst_host_srv_serror_rate=0.0,
        dst_host_rerror_rate=0.0, dst_host_srv_rerror_rate=0.0,
    ),
}


def _predict(template):
    df = pd.DataFrame([template])
    df = pd.get_dummies(df)
    for col in set(_cols) - set(df.columns):
        df[col] = 0
    df = df[_cols]
    probs = _model.predict_proba(df)[0]
    idx   = int(np.argmax(probs))
    label = _le.inverse_transform([idx])[0]
    return label, probs[idx], dict(zip(_le.classes_, probs))


def _model_attack(atype, count, delay):
    colors = {"DoS":"\033[91m","Probe":"\033[93m","R2L":"\033[95m",
              "U2R":"\033[96m","normal":"\033[92m"}
    rst = "\033[0m"
    col = colors.get(atype, "")
    det = mis = 0
    print(f"\n{'─'*55}")
    print(f"  [MODEL {atype}] {count} rows")
    print(f"{'─'*55}")
    for i in range(1, count + 1):
        row = TEMPLATES[atype].copy()
        for k in ("src_bytes","dst_bytes","count","srv_count"):
            row[k] = max(0, row[k] + random.randint(-5, 5))
        pred, conf_val, all_p = _predict(row)
        ok = pred == atype
        det += ok; mis += not ok
        prob_str = "  ".join(f"{c}:{p:.2f}" for c,p in all_p.items())
        status = "✅ DETECTED" if ok else "❌ MISSED"
        print(f"  [{_ts()}] {i}/{count}  {col}{pred}{rst}  conf={conf_val:.2f}  {status}")
        print(f"           {prob_str}")
        time.sleep(delay)
    print(f"  {'─'*40}")
    print(f"  Result: {det}/{count} detected | {mis}/{count} missed")


# ══════════════════════════════════════════════════════════════════
#  MENU
# ══════════════════════════════════════════════════════════════════

def show_menu():
    print("=" * 60)
    print("  AI-BASED IDPS  —  ATTACK SIMULATOR (DEMO MODE)")
    print("=" * 60)
    print(f"  Attacker : {ATTACKER_IP}")
    print(f"  Target   : {TARGET_IP}")
    print(f"  Interface: {LOOPBACK_IFACE}")
    print(f"  Trigger  : {TRIGGER_HOST}:{TRIGGER_PORT}")
    print("=" * 60)

    while True:
        print("\n  L=LIVE (with trigger)   M=MODEL (offline)   0=Exit")
        mode = input("  Mode: ").strip().upper()

        if mode == "0":
            print("  Goodbye!")
            break

        elif mode == "L":
            print("\n  1=DoS   2=Probe   3=R2L   4=U2R   5=Normal   6=ALL   B=Back")
            ch = input("  Choice: ").strip()
            if ch.upper() == "B":
                continue
            try:    d = float(input("  Delay s [0.02]: ").strip() or "0.02")
            except: d = 0.02
            if   ch == "1": _live_dos(200, d)
            elif ch == "2": _live_probe(25, d)
            elif ch == "3": _live_r2l(20, d)
            elif ch == "4": _live_u2r(d)
            elif ch == "5":
                try: n = int(input("  Count [10]: ").strip() or "10")
                except: n = 10
                _live_normal(n, d)
            elif ch == "6":
                print("\n  Running ALL attacks in sequence...\n")
                _live_dos(d);   time.sleep(3)
                _live_probe(d); time.sleep(3)
                _live_r2l(d);   time.sleep(3)
                _live_u2r(d)
            else:
                print("  Invalid choice.")

        elif mode == "M":
            if not _load_model():
                continue
            print("\n  1=DoS   2=Probe   3=R2L   4=U2R   5=Normal   6=ALL   B=Back")
            ch = input("  Choice: ").strip()
            if ch.upper() == "B":
                continue
            try: n = int(input("  Rows [10]: ").strip() or "10")
            except: n = 10
            try: d = float(input("  Delay s [0.3]: ").strip() or "0.3")
            except: d = 0.3
            MAP = {"1":"DoS","2":"Probe","3":"R2L","4":"U2R","5":"normal"}
            if ch in MAP:
                _model_attack(MAP[ch], n, d)
            elif ch == "6":
                for t in ["DoS","Probe","R2L","U2R","normal"]:
                    _model_attack(t, n, d)
            else:
                print("  Invalid choice.")
        else:
            print("  Invalid mode.")


if __name__ == "__main__":
    show_menu()