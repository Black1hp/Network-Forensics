from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
import logging
import threading
from datetime import datetime, timezone, timedelta
import json
import uuid
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket # Not directly used in original server.py but often related to network apps
import sys # Not directly used in original server.py
from queue import Queue, Empty
import concurrent.futures
import time
import smtplib # Added for email sending

# Imports for ML Port Scan Detection
import pandas as pd
import joblib # Requires scikit-learn
from collections import defaultdict

load_dotenv() # Ensure this is called early

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Configure logger
logger = logging.getLogger(__name__)
if not logger.handlers:
    # Corrected format string with standard quotes
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(module)s - %(message)s")

# --- Email Configuration (from .env) ---
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
# General cooldown for non-ML alerts, used by original handle_suspicious_activity
GENERAL_ALERT_COOLDOWN_MINUTES = int(os.getenv("ALERT_COOLDOWN_MINUTES", 5))

# --- ML Port Scan Detection Configuration (from .env or defaults) ---
ML_MODEL_FILENAME = os.getenv("ML_MODEL_FILENAME", "portscan_detector_model.pkl")
ML_SCALER_FILENAME = os.getenv("ML_SCALER_FILENAME", "scaler.pkl")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_MODEL_PATH = os.path.join(BASE_DIR, ML_MODEL_FILENAME)
ML_SCALER_PATH = os.path.join(BASE_DIR, ML_SCALER_FILENAME)

ML_TARGET_IP = os.getenv("ML_TARGET_IP", "169.254.0.21")
ML_SCAN_THRESHOLD = int(os.getenv("ML_SCAN_THRESHOLD", 5))
ML_TIME_INTERVAL = int(os.getenv("ML_TIME_INTERVAL", 5)) # seconds
ML_ALERT_COOLDOWN_MINUTES = int(os.getenv("ML_ALERT_COOLDOWN_MINUTES", GENERAL_ALERT_COOLDOWN_MINUTES))
EVE_JSON_LOG_PATH = os.getenv("EVE_JSON_LOG_PATH", "/var/log/suricata/eve.json")

# --- Globals for ML Port Scan Detection ---
ml_model_instance = None
ml_scaler_instance = None
ml_connection_attempts = defaultdict(list)

# --- AlertTracker Class (Corrected and Centralized) ---
class AlertTracker:
    def __init__(self):
        self.alerts = {}
        logger.info("AlertTracker initialized.")

    def should_send_alert(self, alert_type_key, cooldown_minutes):
        """Checks if an alert for a given key should be sent based on cooldown."""
        if not isinstance(cooldown_minutes, (int, float)) or cooldown_minutes < 0:
            logger.warning(f"Invalid cooldown_minutes value: {cooldown_minutes}. Defaulting to 1 minute.")
            cooldown_minutes = 1 # Default to 1 minute if invalid
            
        if alert_type_key not in self.alerts:
            return True
        
        last_sent_data = self.alerts.get(alert_type_key)
        if not last_sent_data or "last_sent" not in last_sent_data:
            return True
            
        last_sent_time = last_sent_data["last_sent"]
        if not isinstance(last_sent_time, datetime):
            logger.warning(f"Invalid last_sent_time type for {alert_type_key}. Resetting alert.")
            return True

        time_diff = datetime.now() - last_sent_time
        return time_diff.total_seconds() >= (cooldown_minutes * 60)

    def update_alert_timestamp(self, alert_type_key, details):
        """Updates the timestamp for a given alert key."""
        self.alerts[alert_type_key] = {
            "last_sent": datetime.now(),
            "details": details
        }

alert_tracker = AlertTracker()

# --- Email Sending Function (Corrected f-strings) ---
def send_email_alert(subject, body_data, alert_type_for_email_subject="NIDS Alert"):
    if not all([SMTP_SERVER, SENDER_EMAIL, SENDER_PASSWORD, ADMIN_EMAIL]):
        logger.error("Email configuration incomplete. Cannot send email alert.")
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = SENDER_EMAIL
        msg["To"] = ADMIN_EMAIL
        msg["Subject"] = f"🚨 {alert_type_for_email_subject}: {subject}"

        # Corrected f-strings in HTML content
        html = f"""
        <html><head><style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: auto; background-color: #f8f9fa; padding: 20px; border-radius: 5px; border: 1px solid #ddd; }}
        .header {{ background-color: #dc3545; color: white; padding: 15px; border-radius: 5px 5px 0 0; margin: -20px -20px 20px -20px; text-align: center; }}
        .warning-icon {{ font-size: 48px; margin-bottom: 10px; }}
        .details-box {{ background-color: white; padding: 15px; border-radius: 5px; margin-top: 20px; border: 1px solid #ddd; }}
        .info-item {{ margin-bottom: 10px; }}
        .label {{ font-weight: bold; color: #555; }}
        .value {{ color: #333; }}
        .value.danger {{ color: #dc3545; font-weight: bold; }}
        .footer {{ margin-top: 20px; text-align: center; font-size: 12px; color: #777; }}
        .timestamp {{ text-align: right; color: #777; font-size: 12px; margin-top: 10px; }}
        </style></head><body><div class="container">
        <div class="header"><div class="warning-icon">⚠️</div><h2>Security Alert Detected</h2></div>
        <div class="info-item"><span class="label">Alert Type:</span> <span class="value danger">{body_data.get('type', 'N/A')}</span></div>
        <div class="info-item"><span class="label">Description:</span> <span class="value">{body_data.get('details', 'N/A')}</span></div>
        <div class="details-box"><h3>🔍 Additional Information:</h3>
        <div class="info-item"><span class="label">Source IP:</span> <span class="value">{body_data.get('source_ip', 'N/A')}</span></div>
        <div class="info-item"><span class="label">Destination IP:</span> <span class="value">{body_data.get('dest_ip', 'N/A')}</span></div>
        <div class="info-item"><span class="label">Protocol:</span> <span class="value">{body_data.get('protocol', 'N/A')}</span></div>
        <div class="info-item"><span class="label">Port(s):</span> <span class="value">{body_data.get('port', body_data.get('ports_hit', 'N/A'))}</span></div></div>
        <div class="timestamp">Detected at: {body_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
        <div class="footer"><p>This is an automated alert from your NIDS. Please investigate.</p></div>
        </div></body></html>
        """
        # Corrected f-strings in text_content
        text_content = f"{alert_type_for_email_subject}: {subject}\nType: {body_data.get('type', 'N/A')}\nDetails: {body_data.get('details', 'N/A')}\nSource IP: {body_data.get('source_ip', 'N/A')}\nDestination IP: {body_data.get('dest_ip', 'N/A')}\nProtocol: {body_data.get('protocol', 'N/A')}\nPort(s): {body_data.get('port', body_data.get('ports_hit', 'N/A'))}\nTimestamp: {body_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}"

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html, "html"))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        logger.info(f"Alert email sent for {alert_type_for_email_subject}: {subject}")
    except Exception as e:
        logger.error(f"Failed to send email alert for {subject}: {e}", exc_info=True)

# --- ML Port Scan Detection Logic (Integrated and Corrected) ---
def ml_load_model_and_scaler_integrated():
    global ml_model_instance, ml_scaler_instance
    try:
        logger.info(f"Attempting to load ML model from: {ML_MODEL_PATH}")
        ml_model_instance = joblib.load(ML_MODEL_PATH)
        logger.info(f"Attempting to load ML scaler from: {ML_SCALER_PATH}")
        ml_scaler_instance = joblib.load(ML_SCALER_PATH)
        logger.info("Successfully loaded ML model and scaler.")
        return True
    except FileNotFoundError as fnf_error:
        logger.error(f"ML Model/Scaler FileNotFoundError: {fnf_error}. Ensure files are at specified paths.")
    except Exception as e:
        logger.error(f"Error loading ML model/scaler: {e}", exc_info=True)
    return False

def ml_build_features_integrated(src_ip, current_attempts):
    packet_count = len(current_attempts)
    pps = packet_count / ML_TIME_INTERVAL if ML_TIME_INTERVAL > 0 else 0
    features = {
        "Flow Duration": 0,
        "Total Fwd Packets": packet_count,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 0,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Max": 0,
        "Bwd Packet Length Max": 0,
        "Fwd Packet Length Min": 0,
        "Flow Bytes/s": 0,
        "Flow Packets/s": pps
    }
    df = pd.DataFrame([features])
    if ml_scaler_instance:
        try:
            return ml_scaler_instance.transform(df)
        except Exception as e:
            logger.error(f"Error scaling ML features for {src_ip}: {e}", exc_info=True)
            return df.values
    return df.values

def ml_parse_eve_timestamp_integrated(timestamp_str):
    try:
        if "." in timestamp_str and "+" in timestamp_str:
            ts_part, tz_part = timestamp_str.split("+")
            if len(tz_part) == 4: timestamp_str = ts_part + "+00:00"
        elif "+" not in timestamp_str and "Z" in timestamp_str: timestamp_str = timestamp_str.replace("Z", "+00:00")
        return datetime.fromisoformat(timestamp_str).timestamp()
    except ValueError:
        try:
            return datetime.strptime(timestamp_str.split(".")[0], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        except ValueError as e2:
            # Corrected f-string
            logger.warning(f"Error parsing EVE timestamp '{timestamp_str}': {e2}. Using current time.")
            return time.time()

def ml_process_eve_event_integrated(eve_line_str):
    global ml_connection_attempts
    try:
        event = json.loads(eve_line_str)
    except json.JSONDecodeError:
        return

    event_type = event.get("event_type")
    timestamp_str = event.get("timestamp")
    if not timestamp_str: return
    
    current_timestamp_float = ml_parse_eve_timestamp_integrated(timestamp_str)
    src_ip_evt = event.get("src_ip")
    dest_ip_evt = event.get("dest_ip")
    dest_port_evt = event.get("dest_port")
    proto_evt = event.get("proto")

    if not (proto_evt == "TCP" and dest_ip_evt == ML_TARGET_IP and src_ip_evt and dest_port_evt):
        return

    is_syn_packet = False
    tcp_info = event.get("tcp", {})
    if event_type == "flow":
        if tcp_info.get("syn") or "S" in tcp_info.get("tcp_flags_ts", "") or "S" in tcp_info.get("flags", ""):
            is_syn_packet = True
    elif event_type == "alert":
        if tcp_info.get("syn") or "S" in tcp_info.get("tcp_flags", "") or "S" in tcp_info.get("flags", ""):
            is_syn_packet = True
    
    if is_syn_packet:
        ml_connection_attempts[src_ip_evt] = [(p, t) for p, t in ml_connection_attempts[src_ip_evt] if t > current_timestamp_float - ML_TIME_INTERVAL]
        ml_connection_attempts[src_ip_evt].append((dest_port_evt, current_timestamp_float))

        unique_ports_hit = set(p for p, t in ml_connection_attempts[src_ip_evt])
        if len(unique_ports_hit) >= ML_SCAN_THRESHOLD:
            if not ml_model_instance or not ml_scaler_instance:
                logger.warning("ML model or scaler not loaded. Skipping ML prediction for port scan.")
                return

            features_scaled = ml_build_features_integrated(src_ip_evt, ml_connection_attempts[src_ip_evt])
            prediction = 0
            try:
                prediction = ml_model_instance.predict(features_scaled)[0]
            except Exception as e:
                logger.error(f"Error during ML prediction for {src_ip_evt}: {e}", exc_info=True)
            
            if prediction == 1:
                alert_key = f"ml_port_scan_{src_ip_evt}_{ML_TARGET_IP}"
                if alert_tracker.should_send_alert(alert_key, ML_ALERT_COOLDOWN_MINUTES):
                    ports_hit_sorted = sorted(list(unique_ports_hit))
                    alert_subject = f"Port Scan Detected from {src_ip_evt}"
                    
                    alert_data = {
                        "id": str(uuid.uuid4()),
                        "type": "ML Port Scan",
                        "details": f"ML model detected a port scan from {src_ip_evt} targeting {ML_TARGET_IP}. Ports hit: {ports_hit_sorted}",
                        "source_ip": src_ip_evt,
                        "dest_ip": ML_TARGET_IP,
                        "protocol": "TCP",
                        "port": "Multiple",
                        "ports_hit": ports_hit_sorted,
                        "timestamp": datetime.fromtimestamp(current_timestamp_float).isoformat(),
                        "sourceIP": src_ip_evt, 
                        "destinationIP": ML_TARGET_IP,
                        "sourcePort": 0,
                        "destinationPort": 0,
                        "application_protocol": "ML_SCAN",
                        "activity": "ML Port Scan Detected",
                        "isSuspicious": True,
                        "size": 0,
                        "features": {"ports_scanned": ports_hit_sorted},
                        "risk_level": "HIGH"
                    }

                    logger.info(f"[ML-ALERT] {alert_subject} - Target: {ML_TARGET_IP}, Ports hit: {ports_hit_sorted}")
                    send_email_alert(alert_subject, alert_data, alert_type_for_email_subject="ML Port Scan Alert")
                    socketio.emit("new_packet", alert_data)
                    logger.info(f"Sent ML port scan alert to web (new_packet) for {src_ip_evt}")
                            
                    alert_tracker.update_alert_timestamp(alert_key, {"ports": ports_hit_sorted})
                    ml_connection_attempts[src_ip_evt] = []
                else:
                    logger.debug(f"ML Alert for {src_ip_evt} (Port Scan) suppressed due to cooldown.")

def ml_follow_log_file_integrated(filepath):
    try:
        with open(filepath, "r") as file:
            logger.info(f"ML Detector: Tailing EVE log file: {filepath}")
            file.seek(0, os.SEEK_END)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except FileNotFoundError:
        logger.error(f"EVE Log file not found for ML detection: {filepath}. ML detection thread will stop.")
    except Exception as e:
        logger.error(f"Error tailing EVE log file {filepath}: {e}. ML detection thread will stop.", exc_info=True)
    return

def ml_detection_thread_target_integrated():
    logger.info("ML Port Scan Detection Thread: Starting.")
    if not ml_load_model_and_scaler_integrated():
        logger.error("ML Port Scan Detection Thread: Model/Scaler failed to load. Thread stopping.")
        return

    logger.info(f"ML Detector: Monitoring EVE log '{EVE_JSON_LOG_PATH}' for scans targeting {ML_TARGET_IP}")
    logger.info(f"ML Detector: Scan Threshold: {ML_SCAN_THRESHOLD}, Time Interval: {ML_TIME_INTERVAL}s, Cooldown: {ML_ALERT_COOLDOWN_MINUTES}min")

    if not os.path.exists(EVE_JSON_LOG_PATH):
        try:
            log_dir = os.path.dirname(EVE_JSON_LOG_PATH)
            if log_dir and not os.path.exists(log_dir): os.makedirs(log_dir, exist_ok=True)
            with open(EVE_JSON_LOG_PATH, "a") as f: pass
            logger.info(f"Created empty EVE log file for ML detector: {EVE_JSON_LOG_PATH}")
        except Exception as e:
            logger.error(f"Could not create EVE log file {EVE_JSON_LOG_PATH}: {e}. ML thread stopping.", exc_info=True)
            return

    for eve_line in ml_follow_log_file_integrated(EVE_JSON_LOG_PATH):
        try:
            ml_process_eve_event_integrated(eve_line)
        except Exception as e:
            logger.error(f"Unhandled exception in ml_process_eve_event_integrated: {e}", exc_info=True)
            
    logger.info("ML Port Scan Detection Thread: Exiting (log tailing ended or critical error).")

blocked_ips = []
blocked_ports = []

def handle_suspicious_activity(activity_type, details, source_ip=None, dest_ip=None, protocol=None, port=None):
    alert_components = []
    if source_ip: alert_components.append(f"src:{source_ip}")
    if dest_ip: alert_components.append(f"dst:{dest_ip}")
    if protocol: alert_components.append(f"proto:{protocol}")
    if port: alert_components.append(f"port:{port}")
    alert_key = f"{activity_type}_{'.'.join(alert_components)}"
    
    if alert_tracker.should_send_alert(alert_key, GENERAL_ALERT_COOLDOWN_MINUTES):
        subject = f"{activity_type}"
        body_data = {
            "type": activity_type,
            "details": details,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "protocol": protocol,
            "port": port,
            "timestamp": datetime.now().isoformat()
        }
        send_email_alert(subject, body_data)
        alert_tracker.update_alert_timestamp(alert_key, details)

def check_port_suspicious(source_port, dest_port):
    is_suspicious = any(
        (str(bp["port"]) == str(source_port) and bp["type"] == "source") or
        (str(bp["port"]) == str(dest_port) and bp["type"] == "destination")
        for bp in blocked_ports
    )
    if is_suspicious:
        handle_suspicious_activity(
            "Blocked Port Activity",
            f"Connection attempt using blocked port(s): source={source_port}, dest={dest_port}",
            port=f"{source_port}->{dest_port}"
        )
    return is_suspicious

def detect_application_protocol(suricata_data):
    # Add null checks for all values
    l7_proto = suricata_data.get("L7_PROTO", "")
    l7_proto = l7_proto.upper() if l7_proto is not None else ""
    if l7_proto: return l7_proto
    
    protocol = suricata_data.get("PROTOCOL", "")
    protocol = protocol.upper() if protocol is not None else ""
    
    src_port = suricata_data.get("L4_SRC_PORT", 0) or 0
    dst_port = suricata_data.get("L4_DST_PORT", 0) or 0
    common_ports = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL"}
    if src_port in common_ports: return common_ports[src_port]
    if dst_port in common_ports: return common_ports[dst_port]
    return protocol

def detect_activity_type(suricata_data):
    # Add null checks for all values
    protocol = suricata_data.get("PROTOCOL", "")
    protocol = protocol.upper() if protocol is not None else ""
    
    l7_proto = suricata_data.get("L7_PROTO", "")
    l7_proto = l7_proto.upper() if l7_proto is not None else ""
    
    src_port = suricata_data.get("L4_SRC_PORT", 0)
    dst_port = suricata_data.get("L4_DST_PORT", 0)
    in_bytes = suricata_data.get("IN_BYTES", 0) or 0
    out_bytes = suricata_data.get("OUT_BYTES", 0) or 0
    duration = suricata_data.get("FLOW_DURATION_MILLISECONDS", 0) or 0
    if l7_proto == "DNS" or src_port == 53 or dst_port == 53: return "DNS Query"
    if src_port in [3306, 5432, 27017, 6379] or dst_port in [3306, 5432, 27017, 6379]: return "Database Activity"
    if protocol == "UDP" and (src_port in [5060, 5061] or dst_port in [5060, 5061] or (16384 <= src_port <= 16387) or (16384 <= dst_port <= 16387)): return "VoIP Call"
    if (in_bytes + out_bytes) > 100000: return "File Transfer"
    if duration > 1000 and ((in_bytes / duration > 1000) or (out_bytes / duration > 1000)): return "Video Streaming"
    return "Messaging"

class SuricataHandler:
    def __init__(self, num_workers=4):
        self.packet_queue = Queue()
        self.packet_buffer = []
        self.continue_processing = True
        self.workers = []
        self.processing_lock = threading.Lock()
        for _ in range(num_workers):
            worker = threading.Thread(target=self.process_queue, daemon=True)
            worker.start()
            self.workers.append(worker)
        logger.info(f"SuricataHandler initialized with {num_workers} workers.")

    def process_suricata_data(self, suricata_event_data):
        try:
            if not suricata_event_data:
                logger.warning("Received empty suricata data in process_suricata_data")
                return

            # Check if data is in the format from suricata_integration.py
            if "IPV4_SRC_ADDR" in suricata_event_data:
                # Data is coming from suricata_integration.py
                source_ip = suricata_event_data.get("IPV4_SRC_ADDR")
                dest_ip = suricata_event_data.get("IPV4_DST_ADDR")
                source_port = suricata_event_data.get("L4_SRC_PORT")
                dest_port = suricata_event_data.get("L4_DST_PORT")
                protocol = suricata_event_data.get("PROTOCOL")
                timestamp = datetime.now().isoformat()
                event_type = "flow"
            else:
                # Data is in the original format
                source_ip = suricata_event_data.get("src_ip")
                dest_ip = suricata_event_data.get("dest_ip")
                source_port = suricata_event_data.get("src_port")
                dest_port = suricata_event_data.get("dest_port")
                protocol = suricata_event_data.get("proto")
                timestamp = suricata_event_data.get("timestamp")
                event_type = suricata_event_data.get("event_type")
            
            # Create adapted_data with consistent field names
            adapted_data = {
                "L4_SRC_PORT": source_port,
                "L4_DST_PORT": dest_port,
                "PROTOCOL": protocol,
                "L7_PROTO": suricata_event_data.get("L7_PROTO", suricata_event_data.get("app_proto", ""))
            }

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                app_protocol_future = executor.submit(detect_application_protocol, adapted_data)
                activity_future = executor.submit(detect_activity_type, adapted_data)
                port_suspicious_future = executor.submit(check_port_suspicious, source_port, dest_port)
                application_protocol = app_protocol_future.result()
                activity_type = activity_future.result()
                port_suspicious = port_suspicious_future.result()
            
            risk_level = "HIGH" if activity_type in ["Intrusion Attempt", "Malware Activity"] else \
                         "MEDIUM" if activity_type in ["Data Exfiltration", "Suspicious Connection"] else "LOW"
            is_suspicious = port_suspicious or activity_type in ["Intrusion Attempt", "Malware Activity", "Data Exfiltration"]
            
            if is_suspicious:
                threading.Thread(
                    target=handle_suspicious_activity,
                    args=(activity_type, f"Suspicious traffic from {source_ip}:{source_port} to {dest_ip}:{dest_port}",
                          source_ip, dest_ip, protocol, dest_port), daemon=True
                ).start()
            
            # Calculate total bytes based on data format
            if "IPV4_SRC_ADDR" in suricata_event_data:
                total_bytes = suricata_event_data.get("IN_BYTES", 0) + suricata_event_data.get("OUT_BYTES", 0)
            else:
                total_bytes = suricata_event_data.get("flow", {}).get("bytes_toserver", 0) + suricata_event_data.get("flow", {}).get("bytes_toclient", 0)
        
            packet_for_ui = {
                "id": str(uuid.uuid4()),
                "timestamp": timestamp,
                "sourceIP": source_ip,
                "destinationIP": dest_ip,
                "sourcePort": source_port,
                "destinationPort": dest_port,
                "protocol": protocol,
                "application_protocol": application_protocol,
                "activity": activity_type,
                "isSuspicious": is_suspicious,
                "size": total_bytes,
                "features": {
                    "event_type": event_type,
                    "alert_signature": suricata_event_data.get("alert", {}).get("signature")
                },
                "risk_level": risk_level
            }
            socketio.emit("new_packet", packet_for_ui)
            
            with self.processing_lock:
                self.packet_buffer.append(packet_for_ui)
                if len(self.packet_buffer) > 1000: self.packet_buffer.pop(0)

        except Exception as e:
            logger.error(f"Error in SuricataHandler.process_suricata_data: {e}", exc_info=True)

    def add_suricata_data(self, data):
        if data:
            self.packet_queue.put(data)

    def process_queue(self):
        while self.continue_processing:
            try:
                items_to_process = []
                for _ in range(10):
                    if self.packet_queue.empty(): break
                    try: items_to_process.append(self.packet_queue.get_nowait())
                    except Empty: break
                
                if items_to_process:
                    for item_data in items_to_process:
                        self.process_suricata_data(item_data)
                else:
                    time.sleep(0.01)
            except Exception as e:
                logger.error(f"Error in SuricataHandler.process_queue: {e}", exc_info=True)
    
suricata_handler = SuricataHandler()

@app.route("/log", methods=["POST"])
def log_suricata_event():
    data = request.json
    if data:
        suricata_handler.add_suricata_data(data)
        return jsonify({"status": "success", "message": "Data added to processing queue"}), 200
    return jsonify({"status": "error", "message": "No data provided"}), 400

@app.route("/block_ip", methods=["POST"])
def block_ip_route():
    data = request.json
    ip_to_block = data.get("ip")
    if ip_to_block and ip_to_block not in blocked_ips:
        blocked_ips.append(ip_to_block)
        logger.info(f"Blocked IP: {ip_to_block}")
        socketio.emit("ip_blocked", {"ip": ip_to_block})
        return jsonify({"status": "success", "message": f"IP {ip_to_block} blocked"}), 200
    return jsonify({"status": "error", "message": "Invalid IP or already blocked"}), 400

@app.route("/block_port", methods=["POST"])
def block_port_route():
    data = request.json
    port_to_block = data.get("port")
    block_type = data.get("type", "destination")
    if port_to_block:
        blocked_ports.append({"port": str(port_to_block), "type": block_type})
        logger.info(f"Blocked Port: {port_to_block} (Type: {block_type})")
        socketio.emit("port_blocked", {"port": str(port_to_block), "type": block_type})
        return jsonify({"status": "success", "message": f"Port {port_to_block} (Type: {block_type}) blocked"}), 200
    return jsonify({"status": "error", "message": "Invalid port"}), 400

@app.route("/blocked_items", methods=["GET"])
def get_blocked_items():
    return jsonify({"blocked_ips": blocked_ips, "blocked_ports": blocked_ports}), 200

@app.route("/packets", methods=["GET"])
def get_packets():
    with suricata_handler.processing_lock:
        return jsonify(suricata_handler.packet_buffer)

@socketio.on("connect")
def handle_connect():
    logger.info("Client connected to SocketIO")

@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Client disconnected from SocketIO")

if __name__ == "__main__":
    if not os.environ.get("WERKZEUG_RUN_MAIN") or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        if os.path.exists(ML_MODEL_PATH) and os.path.exists(ML_SCALER_PATH):
            logger.info("Starting ML Port Scan Detection Thread...")
            ml_thread = threading.Thread(target=ml_detection_thread_target_integrated, daemon=True)
            ml_thread.start()
        else:
            logger.warning(f"ML model ({ML_MODEL_PATH}) or scaler ({ML_SCALER_PATH}) not found. ML detection thread will NOT start.")
            logger.warning("Ensure 'portscan_detector_model.pkl' and 'scaler.pkl' are in the backend directory, or configure paths via .env.")
    
    logger.info("Starting Flask-SocketIO server...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=True, allow_unsafe_werkzeug=True)


