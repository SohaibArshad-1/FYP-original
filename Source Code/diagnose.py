"""
diagnose.py  — Run this BEFORE attacks.py to find the correct interface.

Step 1: Run this script as Administrator
Step 2: It sends 5 test packets and listens for them simultaneously
Step 3: It tells you exactly which interface + filter works
Step 4: Copy the iface name into attacks.py and monitoring.py

Usage:
    python diagnose.py
"""

import threading
import time
from scapy.all import IP, UDP, send, sniff, conf, get_if_list, get_if_addr

ATTACKER_IP = "192.168.100.250"
TARGET_IP   = "192.168.100.29"
TEST_PORT   = 9999

conf.verb = 0

print("=" * 60)
print("  IDPS INTERFACE DIAGNOSTIC")
print("=" * 60)

# ── Step 1: Show all available interfaces ──────────────────────────
print("\n[1] Available network interfaces on this machine:\n")
ifaces = get_if_list()
for i, iface in enumerate(ifaces):
    try:
        addr = get_if_addr(iface)
    except Exception:
        addr = "?"
    print(f"    [{i}] {iface}  →  {addr}")

# ── Step 2: Try sniffing on EACH interface for 4 seconds ──────────
print("\n[2] Testing which interface captures spoofed packets...\n")
print("    (Sending 10 test UDP packets to each interface as we check)\n")

results = {}

def send_test_packets(iface_to_use):
    """Send 10 packets — delayed 1s to let sniffer start first."""
    time.sleep(1.0)
    pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / UDP(dport=TEST_PORT, sport=54321)
    for _ in range(10):
        try:
            send(pkt, iface=iface_to_use, verbose=False)
        except Exception:
            send(pkt, verbose=False)
        time.sleep(0.05)

for iface in ifaces:
    try:
        captured = []

        sender = threading.Thread(target=send_test_packets, args=(iface,), daemon=True)
        sender.start()

        pkts = sniff(
            iface=iface,
            filter=f"udp and dst port {TEST_PORT}",
            timeout=3,
            count=5,
            store=True,
        )

        count = len(pkts)
        results[iface] = count

        if count > 0:
            print(f"    ✅  {iface:<40} — CAPTURED {count} packets  ← USE THIS")
        else:
            print(f"    ❌  {iface:<40} — nothing captured")

    except Exception as e:
        results[iface] = 0
        print(f"    ⚠️  {iface:<40} — error: {e}")

# ── Step 3: Summary ────────────────────────────────────────────────
print("\n[3] Summary:\n")
working = [iface for iface, cnt in results.items() if cnt > 0]

if working:
    print(f"    Working interface(s): {working}\n")
    best = working[0]
    print(f"    → Recommended: use iface='{best}'\n")
    print("    → In monitoring_controller.py, change AsyncSniffer to:\n")
    print(f"       self.sniffer = AsyncSniffer(")
    print(f"           iface='{best}',")
    print(f"           filter='ip',")
    print(f"           store=False,")
    print(f"           prn=lambda pkt: self.packet_received.emit(pkt)")
    print(f"       )")
    print()
    print("    → In attacks.py _send_dos(), _send_probe() etc, add:")
    print(f"       send(pkt, iface='{best}', verbose=False)")
else:
    print("    No interface captured the test packets.")
    print("    Possible causes:")
    print("    1. Not running as Administrator")
    print("    2. Npcap not installed or 'WinPcap API-compatible mode' not enabled")
    print("    3. Firewall blocking raw socket sends")
    print()
    print("    Try: reinstall Npcap with 'WinPcap API-compatible mode' checked")

print("=" * 60)