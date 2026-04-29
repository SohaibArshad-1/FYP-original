import sqlite3
import threading
from PyQt5.QtCore import QObject, QThread, QThreadPool, QRunnable, pyqtSignal, pyqtSlot
from scapy.all import conf, sniff
from prevention import PreventionEngine

conf.promisc = True

LOOPBACK_IFACE = r"\Device\NPF_Loopback"


class PacketWorker(QRunnable):
    def __init__(self, pkt, controller):
        super().__init__()
        self.pkt = pkt
        self.controller = controller
        self.setAutoDelete(True)

    @pyqtSlot()
    def run(self):
        from monitoring import process_packet
        try:
            result = process_packet(self.pkt, self.controller)
            if not result:
                return
            is_attack = "ALERT:" in result
            self.controller._count_lock.acquire()
            if is_attack:
                self.controller.attack_count += 1
            else:
                self.controller.normal_count += 1
            self.controller.packet_counter += 1
            pc = self.controller.packet_counter
            nc = self.controller.normal_count
            ac = self.controller.attack_count
            self.controller._count_lock.release()
            if pc % 5 == 0:
                self.controller.data_updated.emit(nc, ac)
        except Exception as e:
            print(f"[WORKER ERROR] {e}")


class MonitoringController(QObject):
    status_updated  = pyqtSignal(str)
    alert_triggered = pyqtSignal(str, list)
    data_updated    = pyqtSignal(int, int)
    live_detection  = pyqtSignal(str, str, int, int, str)

    def __init__(self, main_page):
        super().__init__()
        self.main_page      = main_page
        self.sniffer_thread = None
        self.is_running     = False
        self._count_lock    = threading.Lock()
        self.normal_count   = 0
        self.attack_count   = 0
        self.packet_counter = 0
        self.thread_pool    = QThreadPool()
        self.thread_pool.setMaxThreadCount(2)
        self.db_connection  = sqlite3.connect("IDS.db", timeout=10, check_same_thread=False)
        self._db_lock       = threading.Lock()
        self._init_db()
        self.prevention     = PreventionEngine()

    def _init_db(self):
        cursor = self.db_connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detected_attacks (
                timestamp TEXT, protocol_type TEXT, src_bytes INTEGER,
                dst_bytes INTEGER, service TEXT, flag INTEGER,
                count INTEGER, srv_count INTEGER,
                same_srv_rate REAL, diff_srv_rate REAL, prediction TEXT
            )
        """)
        self.db_connection.commit()

    def start_monitoring(self):
        if self.is_running:
            return
        with self._count_lock:
            self.normal_count   = 0
            self.attack_count   = 0
            self.packet_counter = 0
        from monitoring import reset_state, start_trigger_listener
        reset_state()
        start_trigger_listener(self)
        self.sniffer_thread = MonitoringThread(self)
        self.sniffer_thread.packet_received.connect(self._on_packet_received)
        self.sniffer_thread.start()
        self.is_running = True
        self.status_updated.emit("🟢 Monitoring started")

    def stop_monitoring(self):
        if not self.is_running:
            return
        from monitoring import stop_trigger_listener
        stop_trigger_listener()
        self.sniffer_thread.stop()
        self.sniffer_thread.quit()
        self.sniffer_thread.wait(3000)
        self.sniffer_thread = None
        self.is_running     = False
        self.status_updated.emit("🔴 Monitoring stopped")

    @pyqtSlot(object)
    def _on_packet_received(self, pkt):
        worker = PacketWorker(pkt, self)
        self.thread_pool.start(worker)

    def trigger_prevention(self, attack_type, src_ip):
        self.prevention.handle_alert(attack_type, src_ip)

    def log_attack(self, attack_data):
        try:
            with self._db_lock:
                cursor = self.db_connection.cursor()
                cursor.execute("INSERT INTO detected_attacks VALUES (?,?,?,?,?,?,?,?,?,?,?)", attack_data)
                self.db_connection.commit()
        except Exception as e:
            print(f"[DB ERROR] {e}")

    def close(self):
        if self.is_running:
            self.stop_monitoring()
        self.thread_pool.waitForDone(2000)
        self.prevention.close()
        try:
            self.db_connection.close()
        except Exception:
            pass


class _LoopbackThread(threading.Thread):
    """Plain blocking thread for loopback — sniff() works here, AsyncSniffer does not."""
    def __init__(self, emit_fn):
        super().__init__(daemon=True)
        self._emit   = emit_fn
        self._stop   = threading.Event()

    def run(self):
        print("[LOOPBACK] sniffer started")
        try:
            sniff(
                iface=LOOPBACK_IFACE,
                store=False,
                stop_filter=lambda p: self._stop.is_set(),
                prn=self._emit,
            )
        except Exception as e:
            print(f"[LOOPBACK ERROR] {e}")
        print("[LOOPBACK] sniffer stopped")

    def stop(self):
        self._stop.set()


class _RealIfaceThread(threading.Thread):
    """Plain blocking thread for all real interfaces — normal traffic for graph."""
    def __init__(self, emit_fn):
        super().__init__(daemon=True)
        self._emit = emit_fn
        self._stop = threading.Event()

    def run(self):
        print("[SNIFFER] real-interface sniffer started")
        try:
            sniff(
                filter="ip",
                store=False,
                stop_filter=lambda p: self._stop.is_set(),
                prn=self._emit,
            )
        except Exception as e:
            print(f"[SNIFFER ERROR] {e}")
        print("[SNIFFER] real-interface sniffer stopped")

    def stop(self):
        self._stop.set()


class MonitoringThread(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self, controller):
        super().__init__()
        self._loopback = None
        self._real     = None

    def run(self):
        def emit(pkt):
            self.packet_received.emit(pkt)

        self._loopback = _LoopbackThread(emit)
        self._real     = _RealIfaceThread(emit)
        self._loopback.start()
        self._real.start()

        # Keep QThread alive until stop() is called
        self._loopback.join()
        self._real.join()

    def stop(self):
        try:
            if self._loopback:
                self._loopback.stop()
                self._loopback.join(timeout=2)
        except Exception as e:
            print(f"[STOP LOOPBACK] {e}")
        try:
            if self._real:
                self._real.stop()
                self._real.join(timeout=2)
        except Exception as e:
            print(f"[STOP REAL] {e}")