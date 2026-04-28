import time
import threading
import socket
from socket import SO_REUSEADDR
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP

TRIGGER_PORT = 65432
ATTACKER_IP   = "192.168.100.250"

MODEL_PATH       = "models/rf_model_resampled.pkl"
COLS_PATH        = "models/encoded_columns_resampled.pkl"
LE_PATH          = "models/label_encoder_resampled.pkl"

ML_MODEL         = None
ML_COLS          = None
ML_LE            = None
ML_LOADED        = False

ML_CONFIDENCE_THRESHOLD = 0.60
ML_CONFIDENCE_HIGH      = 0.75

ALERT_COOLDOWN = 60

ALERT_COUNTS = {
    "DoS":    3,
    "Probe":  3,
    "R2L":    3,
    "U2R":    2,
}
ALERT_WINDOW = 10

def _load_ml_model():
    global ML_MODEL, ML_COLS, ML_LE, ML_LOADED
    if ML_LOADED:
        return True
    try:
        print("[ML] Loading Random Forest model...")
        ML_MODEL = joblib.load(MODEL_PATH)
        ML_COLS  = joblib.load(COLS_PATH)
        ML_LE    = joblib.load(LE_PATH)
        print(f"[ML] Model loaded. Classes: {list(ML_LE.classes_)}")
        ML_LOADED = True
        return True
    except FileNotFoundError as e:
        print(f"[ML] Model files not found: {e}")
        return False
    except Exception as e:
        print(f"[ML] Error loading model: {e}")
        return False

_load_ml_model()

def _get_local_ips():
    ips = {"127.0.0.1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        own = s.getsockname()[0]
        s.close()
        ips.add(own)
        parts = own.split(".")
        ips.add(f"{parts[0]}.{parts[1]}.{parts[2]}.1")
        print(f"[WHITELIST] Own={own}")
    except Exception as e:
        print(f"[WHITELIST] Error: {e}")
    return ips

WHITELIST = _get_local_ips()

_lock             = threading.Lock()
_history          = defaultdict(list)
_last_alert       = {}
_pkt_counter      = 0
_controller       = None
_trigger_sock     = None
_pred_history     = defaultdict(list)

ALERT_COOLDOWN = 60

ML_CONFIDENCE_THRESHOLD = 0.60

ALERT_COUNTS = {
    "DoS":    15,
    "Probe":  15,
    "R2L":    8,
    "U2R":    5,
}
ALERT_WINDOW = 60

def _cooldown_ok(src_ip, atype, now):
    key  = (src_ip, atype)
    last = _last_alert.get(key, 0)
    if now - last >= ALERT_COOLDOWN:
        _last_alert[key] = now
        return True
    return False


def _fire_alert(attack_type, src_ip, confidence, controller):
    now = time.time()
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not _cooldown_ok(src_ip, attack_type, now):
        return

    print(f"[{ts}] ALERT FIRED: {attack_type} (conf={confidence:.2f}) from {src_ip}")

    proto, port, service = _get_attack_meta(attack_type)
    attack_data = (ts, proto, 0, 0, service, 0,
                   0, 0, 0.0, 0.0, attack_type)
    controller.log_attack(attack_data)
    controller.alert_triggered.emit(attack_type, _get_preventions(attack_type))
    controller.live_detection.emit(attack_type, proto, 0, 0, service)
    controller.trigger_prevention(attack_type, src_ip)

    controller._count_lock.acquire()
    controller.attack_count   += 1
    controller.packet_counter += 1
    pc = controller.packet_counter
    ac = controller.attack_count
    nc = controller.normal_count
    controller._count_lock.release()
    controller.data_updated.emit(nc, ac)


def _get_attack_meta(atype):
    ATTACK_META = {
        "DoS":   ("udp",  80,   "http"),
        "Probe": ("tcp",  80,   "http"),
        "R2L":   ("tcp",  21,   "ftp"),
        "U2R":   ("tcp",  22,   "ssh"),
        "normal":("tcp",  80,   "http"),
    }
    return ATTACK_META.get(atype, ("tcp", 80, "http"))


def _get_preventions(atype):
    tips = {
        "DoS":   [("Block source IP with firewall rule",),
                  ("Rate-limit UDP/ICMP flood packets",),
                  ("Enable IPS blocking mode",)],
        "Probe": [("Enable port-scan detection",),
                  ("Block IP after repeated SYN failures",),
                  ("Close unused ports",)],
        "R2L":   [("Enforce strong passwords + MFA",),
                  ("Disable anonymous FTP/Telnet",),
                  ("Enable account lockout after 5 attempts",)],
        "U2R":   [("Apply least-privilege principle",),
                  ("Monitor sudo/su usage in logs",),
                  ("Patch privilege escalation CVEs",)],
    }
    return tips.get(atype, [("Review network logs immediately",)])


def _packet_to_features(pkt, proto, port, payload_len, flags):
    now = time.time()
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "0.0.0.0"

    service_map = {
        80:"http", 443:"https", 53:"domain", 21:"ftp",
        22:"ssh", 23:"telnet", 25:"smtp", 110:"pop_3",
        3389:"rdp", 3306:"mysql", 5900:"vnc",
    }
    service = service_map.get(port, "other")

    flag_map = {
        0:"OTH", 1:"S0", 2:"SHR", 3:"RSTO", 4:"RSTOS0",
        5:"SH", 6:"S1", 7:"R", 8:"FIN", 9:"S2", 10:"S3",
        11:"OTH", 12:"SF", 13:"REJ", 14:"RSTR", 15:"RST",
    }
    flag = flag_map.get(flags, "SF")

    with _lock:
        h = _history[src_ip]
        recent = [(t, p) for t, p in h if now - t <= ALERT_WINDOW]
        count = len(recent)
        srv_count = count

        dst_ports = {p for _, p in recent}
        same_srv_rate = 1.0 if count > 0 and port in dst_ports else 0.0
        diff_srv_rate = 1.0 - same_srv_rate

        h.append((now, port))
        cutoff = now - ALERT_WINDOW
        _history[src_ip] = [(t, p) for t, p in _history[src_ip] if t > cutoff]

    features = {
        "duration": 0,
        "protocol_type": proto,
        "service": service,
        "flag": flag,
        "src_bytes": max(0, payload_len),
        "dst_bytes": max(0, payload_len),
        "land": 1 if src_ip == dst_ip else 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1 if port in {80, 443, 22, 21} else 0,
        "lnum_compromised": 0,
        "lroot_shell": 0,
        "lsu_attempted": 0,
        "lnum_root": 0,
        "lnum_file_creations": 0,
        "lnum_shells": 0,
        "lnum_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": min(count, 511),
        "srv_count": min(srv_count, 511),
        "serror_rate": 1.0 if flags in (1, 2) else 0.0,
        "srv_serror_rate": 1.0 if flags in (1, 2) else 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": min(count, 255),
        "dst_host_srv_count": min(count, 255),
        "dst_host_same_srv_rate": same_srv_rate,
        "dst_host_diff_srv_rate": diff_srv_rate,
        "dst_host_same_src_port_rate": same_srv_rate,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 1.0 if flags in (1, 2) else 0.0,
        "dst_host_srv_serror_rate": 1.0 if flags in (1, 2) else 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }
    return features


def _ml_predict(pkt, proto, port, payload_len, flags):
    if not ML_LOADED:
        return "normal", 0.0

    try:
        features = _packet_to_features(pkt, proto, port, payload_len, flags)
        df = pd.DataFrame([features])
        df = pd.get_dummies(df)

        for col in set(ML_COLS) - set(df.columns):
            df[col] = 0
        for col in df.columns:
            if col not in ML_COLS:
                df = df.drop(columns=[col])
        df = df.reindex(columns=ML_COLS, fill_value=0)

        probs = ML_MODEL.predict_proba(df)[0]
        idx   = int(np.argmax(probs))
        label = ML_LE.inverse_transform([idx])[0]
        conf  = probs[idx]

        return label, conf
    except Exception as e:
        print(f"[ML PREDICT ERROR] {e}")
        return "normal", 0.0


class _TriggerListener(threading.Thread):
    def __init__(self, controller):
        super().__init__(daemon=True)
        self._controller  = controller
        self._stop        = threading.Event()
        self._pred_times  = defaultdict(lambda: defaultdict(list))

    def run(self):
        global _trigger_sock
        try:
            _trigger_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _trigger_sock.setsockopt(socket.SOL_SOCKET, SO_REUSEADDR, 1)
            _trigger_sock.bind(("127.0.0.1", TRIGGER_PORT))
            _trigger_sock.settimeout(1.0)
            print(f"[TRIGGER] Listening on 127.0.0.1:{TRIGGER_PORT}")
        except Exception as e:
            print(f"[TRIGGER ERROR] Cannot bind: {e}")
            return

        while not self._stop.is_set():
            try:
                data, _ = _trigger_sock.recvfrom(1024)
                msg = json.loads(data.decode())
                attack = msg.get("attack", "normal")
                src    = msg.get("src", ATTACKER_IP)
                conf   = msg.get("confidence", 1.0)
                self._handle(attack, src, conf)
            except socket.timeout:
                continue
            except Exception as e:
                if not self._stop.is_set():
                    print(f"[TRIGGER ERROR] {e}")

        try:
            _trigger_sock.close()
        except Exception:
            pass
        print("[TRIGGER] Listener stopped")

    def _handle(self, attack_type, src_ip, confidence):
        now = time.time()

        if attack_type == "normal":
            self._controller._count_lock.acquire()
            self._controller.normal_count   += 1
            self._controller.packet_counter += 1
            pc = self._controller.packet_counter
            nc = self._controller.normal_count
            ac = self._controller.attack_count
            self._controller._count_lock.release()
            if pc % 5 == 0:
                self._controller.data_updated.emit(nc, ac)
            return

        threshold = ALERT_COUNTS.get(attack_type, 3)

        self._pred_times[attack_type][src_ip].append(now)
        window = self._pred_times[attack_type][src_ip]
        window[:] = [t for t in window if now - t <= ALERT_WINDOW]
        count = len(window)

        if count >= threshold:
            self._controller._count_lock.acquire()
            self._controller.attack_count   += 1
            self._controller.packet_counter += 1
            pc = self._controller.packet_counter
            nc = self._controller.normal_count
            ac = self._controller.attack_count
            self._controller._count_lock.release()
            if pc % 5 == 0:
                self._controller.data_updated.emit(nc, ac)
            _fire_alert(attack_type, src_ip, confidence, self._controller)
            self._pred_times[attack_type][src_ip] = []

    def stop(self):
        self._stop.set()


_trigger_listener = None


def start_trigger_listener(controller):
    global _trigger_listener, _controller
    _controller = controller
    if _trigger_listener and _trigger_listener.is_alive():
        return
    _trigger_listener = _TriggerListener(controller)
    _trigger_listener.start()


def stop_trigger_listener():
    global _trigger_listener
    if _trigger_listener:
        _trigger_listener.stop()
        _trigger_listener = None


def process_packet(pkt, controller=None):
    global _pkt_counter

    if not pkt.haslayer(IP):
        return None

    src_ip = pkt[IP].src
    if src_ip in WHITELIST:
        return None

    with _lock:
        _pkt_counter += 1
        count = _pkt_counter

    now = time.time()
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if pkt.haslayer(TCP):
        proto, port, payload, flags = "tcp", pkt[TCP].dport, bytes(pkt[TCP].payload), int(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto, port, payload, flags = "udp", pkt[UDP].dport, bytes(pkt[UDP].payload), 0
    elif pkt.haslayer(ICMP):
        proto, port, payload, flags = "icmp", 0, bytes(pkt[ICMP].payload), 0
    else:
        return None

    payload_len = len(payload)

    prediction, confidence = _ml_predict(pkt, proto, port, payload_len, flags)

    with _lock:
        _pred_history[src_ip].append((now, prediction, confidence))
        cutoff = now - ALERT_WINDOW
        _pred_history[src_ip] = [(t, p, c) for t, p, c in _pred_history[src_ip] if t > cutoff]
        recent = _pred_history[src_ip]

    if count % 20 == 0:
        print(f"[{ts}] #{count:>5} | {prediction.upper():8s} | "
              f"proto={proto} port={port} | src={src_ip} "
              f"pkts={len(recent)} conf={confidence:.2f}")

    is_sustained_attack = False
    if prediction != "normal" and confidence >= ML_CONFIDENCE_HIGH:
        attack_preds = [p for t, p, c in recent if p == prediction and c >= ML_CONFIDENCE_THRESHOLD]
        if len(attack_preds) >= 15:
            is_sustained_attack = True

    if not is_sustained_attack:
        info = (f"<span style='color:#29ABE2;font-weight:bold;'>Normal</span>"
                f" | {proto} | {src_ip} | port {port}")
    else:
        info = (f"<span style='color:#e63946;font-weight:bold;'>ALERT: {prediction}</span>"
                f" | {proto} | {src_ip} | port {port} | conf={confidence:.2f}")

    if controller:
        if is_sustained_attack and _cooldown_ok(src_ip, prediction, now):
            print(f"[{ts}] ALERT FIRED: {prediction} (conf={confidence:.2f}) from {src_ip}")
            service_map = {
                80:"http", 443:"https", 53:"domain", 21:"ftp",
                22:"ssh", 23:"telnet", 25:"smtp", 110:"pop_3",
                3389:"rdp", 3306:"mysql", 5900:"vnc",
            }
            service = service_map.get(port, "other")
            attack_data = (ts, proto, payload_len, payload_len, service, flags,
                           len(recent), 0, 0.0, 0.0, prediction)
            controller.status_updated.emit(info)
            controller.log_attack(attack_data)
            controller.alert_triggered.emit(prediction, _get_preventions(prediction))
            controller.live_detection.emit(prediction, proto, payload_len, payload_len, service)
            controller.trigger_prevention(prediction, src_ip)

    return info


def reset_state():
    global _pkt_counter, WHITELIST
    with _lock:
        _history.clear()
        _last_alert.clear()
        _pred_history.clear()
        _pkt_counter = 0
        WHITELIST = _get_local_ips()
    print(f"[MONITORING] Reset. Whitelist={WHITELIST}")