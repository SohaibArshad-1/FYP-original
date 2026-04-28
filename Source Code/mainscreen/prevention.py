"""
prevention.py
─────────────────────────────────────────────────────────────────────
Prevention backend for AI-Based IDPS.

How it connects to the rest of the system:
  1. monitoring.py detects attack → fires controller.alert_triggered
  2. MonitoringController connects alert_triggered to
     PreventionEngine.handle_alert()
  3. PreventionEngine decides action based on attack type,
     runs the Windows Firewall command, logs to DB, emits
     prevention_done signal back to NotificationCenter.

Prevention actions per attack type:
  ┌─────────┬──────────────────────────────────────────────────────┐
  │ DoS     │ HARD BLOCK — permanent firewall rule for src IP.     │
  │         │ DoS is high-confidence once threshold fires.         │
  ├─────────┼──────────────────────────────────────────────────────┤
  │ Probe   │ SOFT BLOCK — 10-minute temporary firewall rule.      │
  │         │ Could be a security scanner, so not permanent.       │
  ├─────────┼──────────────────────────────────────────────────────┤
  │ R2L     │ SOFT BLOCK — 30-minute firewall rule + block the     │
  │         │ specific attacked port (e.g. FTP port 21).           │
  ├─────────┼──────────────────────────────────────────────────────┤
  │ U2R     │ LOG ONLY — U2R is a local OS attack, not network.    │
  │         │ Firewall cannot stop it. Alert admin immediately.    │
  └─────────┴──────────────────────────────────────────────────────┘

Requirements:
  - App must be running as Administrator (needed for netsh + Npcap)
  - Windows OS (uses netsh advfirewall)
"""

import sqlite3
import subprocess
import os
from datetime import datetime, timedelta
from PyQt5.QtCore import QObject, pyqtSignal, QTimer


DB_PATH = "IDS.db"

# ── Auto-unblock timeouts per attack type (minutes) ───────────────────
BLOCK_DURATION = {
    "DoS"  : None,   # permanent — admin must manually unblock
    "Probe": 10,     # 10 minutes
    "R2L"  : 30,     # 30 minutes
    "U2R"  : None,   # no block applied — log only
}

# ── Firewall rule name prefix ──────────────────────────────────────────
RULE_PREFIX = "IDPS_BLOCK"


class PreventionEngine(QObject):
    """
    Handles all prevention actions.
    Connect alert_triggered → handle_alert in MonitoringController.
    """

    # Emits (action_message, attack_type, ip_address) for NotificationCenter
    prevention_done = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self.db_conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        self._ensure_table()

        # QTimer checks for expired soft blocks every 60 seconds
        self.unblock_timer = QTimer()
        self.unblock_timer.timeout.connect(self._check_expired_blocks)
        self.unblock_timer.start(60_000)   # every 60 seconds

    # ── Public slot — connect to alert_triggered signal ───────────────
    def handle_alert(self, attack_type, src_ip):
        """
        Called automatically when monitoring detects an attack.
        attack_type : "DoS" / "Probe" / "R2L" / "U2R"
        src_ip      : source IP address of the attacker
        """
        timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration   = BLOCK_DURATION.get(attack_type)

        print(f"\n[PREVENTION] Attack={attack_type}  IP={src_ip}  "
              f"Time={timestamp}")

        # ── Skip if already blocked ────────────────────────────────────
        if self._is_already_blocked(src_ip, attack_type):
            print(f"[PREVENTION] {src_ip} already blocked for {attack_type}. Skipping.")
            return

        # ── Choose action ──────────────────────────────────────────────
        if attack_type == "DoS":
            action  = "hard_block"
            message = self._hard_block(src_ip, attack_type, timestamp)

        elif attack_type == "Probe":
            action  = "soft_block"
            message = self._soft_block(src_ip, attack_type, timestamp,
                                       duration_minutes=10)

        elif attack_type == "R2L":
            action  = "soft_block"
            message = self._soft_block(src_ip, attack_type, timestamp,
                                       duration_minutes=30)

        elif attack_type == "U2R":
            action  = "log_only"
            message = self._log_only(src_ip, attack_type, timestamp)

        else:
            action  = "log_only"
            message = f"Unknown attack type {attack_type} — logged only."

        # ── Log to DB ──────────────────────────────────────────────────
        unblock_at = None
        if duration:
            unblock_at = (
                datetime.now() + timedelta(minutes=duration)
            ).strftime("%Y-%m-%d %H:%M:%S")

        self._log_to_db(src_ip, attack_type, action, timestamp, unblock_at)

        # ── Notify UI ──────────────────────────────────────────────────
        self.prevention_done.emit(message, attack_type, src_ip)
        print(f"[PREVENTION] Action taken: {message}")

    # ── Hard block — permanent firewall rule ───────────────────────────
    def _hard_block(self, ip, attack_type, timestamp):
        rule_name = f"{RULE_PREFIX}_{ip.replace('.', '_')}"
        cmd = (
            f'netsh advfirewall firewall add rule '
            f'name="{rule_name}" '
            f'dir=in action=block remoteip={ip} '
            f'description="IDPS auto-block: {attack_type} at {timestamp}"'
        )
        success = self._run_netsh(cmd)
        if success:
            return (f"🚫 HARD BLOCKED {ip} — {attack_type} "
                    f"(permanent, admin must unblock)")
        else:
            return (f"⚠️ Block attempted for {ip} but netsh failed "
                    f"(run app as Administrator)")

    # ── Soft block — temporary firewall rule ───────────────────────────
    def _soft_block(self, ip, attack_type, timestamp, duration_minutes):
        rule_name  = f"{RULE_PREFIX}_{ip.replace('.', '_')}"
        unblock_at = (
            datetime.now() + timedelta(minutes=duration_minutes)
        ).strftime("%H:%M:%S")

        cmd = (
            f'netsh advfirewall firewall add rule '
            f'name="{rule_name}" '
            f'dir=in action=block remoteip={ip} '
            f'description="IDPS soft-block: {attack_type} at {timestamp}"'
        )
        success = self._run_netsh(cmd)
        if success:
            return (f"⏱️ SOFT BLOCKED {ip} — {attack_type} "
                    f"({duration_minutes} min, auto-unblock at {unblock_at})")
        else:
            return (f"⚠️ Soft block attempted for {ip} but netsh failed "
                    f"(run app as Administrator)")

    # ── Log only — no firewall action ─────────────────────────────────
    def _log_only(self, ip, attack_type, timestamp):
        return (f"📋 LOGGED {ip} — {attack_type} "
                f"(U2R is a local attack, firewall cannot block. "
                f"Check running processes immediately.)")

    # ── Run netsh command ──────────────────────────────────────────────
    def _run_netsh(self, cmd):
        try:
            result = subprocess.run(
                cmd, shell=True,
                capture_output=True, text=True
            )
            if result.returncode == 0:
                return True
            else:
                print(f"[NETSH ERROR] {result.stderr.strip()}")
                return False
        except Exception as e:
            print(f"[NETSH EXCEPTION] {e}")
            return False

    # ── Check for expired soft blocks every 60 seconds ────────────────
    def _check_expired_blocks(self):
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = self.db_conn.cursor()

        # Find all active blocks whose unblock_at has passed
        cursor.execute("""
            SELECT id, ip_address, attack_type
            FROM blocked_ips
            WHERE is_active = 1
              AND unblock_at IS NOT NULL
              AND unblock_at <= ?
        """, (now,))

        expired = cursor.fetchall()

        for row_id, ip, attack_type in expired:
            print(f"[PREVENTION] Auto-unblocking {ip} ({attack_type}) — timeout reached")
            self._unblock_ip(ip)

            # Mark as inactive in DB
            cursor.execute(
                "UPDATE blocked_ips SET is_active = 0 WHERE id = ?",
                (row_id,)
            )
            self.db_conn.commit()

            msg = f"✅ AUTO-UNBLOCKED {ip} — {attack_type} (timeout reached)"
            self.prevention_done.emit(msg, attack_type, ip)

    # ── Remove firewall rule ───────────────────────────────────────────
    def _unblock_ip(self, ip):
        rule_name = f"{RULE_PREFIX}_{ip.replace('.', '_')}"
        cmd = (
            f'netsh advfirewall firewall delete rule '
            f'name="{rule_name}"'
        )
        self._run_netsh(cmd)

    # ── Manual unblock (called from UI if needed) ──────────────────────
    def manual_unblock(self, ip):
        """Call this from UI to manually unblock a hard-blocked IP."""
        self._unblock_ip(ip)
        cursor = self.db_conn.cursor()
        cursor.execute(
            "UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ? AND is_active = 1",
            (ip,)
        )
        self.db_conn.commit()
        msg = f"🔓 MANUALLY UNBLOCKED {ip}"
        self.prevention_done.emit(msg, "manual", ip)
        print(f"[PREVENTION] {msg}")

    # ── Check if IP already blocked for same attack ────────────────────
    def _is_already_blocked(self, ip, attack_type):
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT id FROM blocked_ips
            WHERE ip_address = ?
              AND attack_type = ?
              AND is_active = 1
        """, (ip, attack_type))
        return cursor.fetchone() is not None

    # ── Log block action to DB ─────────────────────────────────────────
    def _log_to_db(self, ip, attack_type, action, blocked_at, unblock_at):
        cursor = self.db_conn.cursor()
        cursor.execute("""
            INSERT INTO blocked_ips
                (ip_address, attack_type, action_taken,
                 blocked_at, unblock_at, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (ip, attack_type, action, blocked_at, unblock_at))
        self.db_conn.commit()

    # ── Get all currently blocked IPs (for UI display) ────────────────
    def get_blocked_ips(self):
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT ip_address, attack_type, action_taken,
                   blocked_at, unblock_at
            FROM blocked_ips
            WHERE is_active = 1
            ORDER BY blocked_at DESC
        """)
        return cursor.fetchall()

    # ── Get full prevention history (for notifications page) ──────────
    def get_prevention_history(self):
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT ip_address, attack_type, action_taken,
                   blocked_at, unblock_at, is_active
            FROM blocked_ips
            ORDER BY blocked_at DESC
        """)
        return cursor.fetchall()

    # ── Ensure table exists ────────────────────────────────────────────
    def _ensure_table(self):
        cursor = self.db_conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address   TEXT    NOT NULL,
                attack_type  TEXT    NOT NULL,
                action_taken TEXT    NOT NULL,
                blocked_at   TEXT    NOT NULL,
                unblock_at   TEXT,
                is_active    INTEGER NOT NULL DEFAULT 1
            )
        """)
        self.db_conn.commit()

    def close(self):
        self.unblock_timer.stop()
        self.db_conn.close()