#!/usr/bin/env python3
"""
ICMP Flood Detection Module for Suricata Integration

This script implements a real-time ICMP flood detection system using a simple
threshold-based approach. It monitors Suricata's eve.json log for ICMP packets 
and detects potential flood attacks based on traffic patterns.

The detector is specifically designed to work with Suricata's EVE JSON format
and can send email alerts when attacks are detected.
"""

import os
import sys
import time
import json
import argparse
import pandas as pd
import numpy as np
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from datetime import datetime, timedelta

class ICMPFloodDetector:
    def __init__(self, model_path=None, scaler_path=None, target_ip=None, 
                 threshold=10, window_size=5, alert_cooldown=60, verbose=False):
        """
        Initialize the ICMP Flood Detector.
        
        Args:
            model_path: Path to the trained model pickle file (optional)
            scaler_path: Path to the feature scaler pickle file (optional)
            target_ip: IP address to monitor (None to monitor all IPs)
            threshold: Minimum packets per second to consider for detection
            window_size: Time window in seconds to aggregate traffic
            alert_cooldown: Minimum seconds between alerts for the same source
            verbose: Whether to print verbose debug information
        """
        # Load the model and scaler if provided
        self.model = None
        self.scaler = None
        if model_path and os.path.exists(model_path) and scaler_path and os.path.exists(scaler_path):
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                print(f"[*] Model loaded from: {model_path}")
            except Exception as e:
                print(f"[!] Error loading model: {str(e)}")
                print("[!] Falling back to threshold-based detection only")
        
        # Configuration
        self.target_ip = target_ip
        self.threshold = threshold
        self.window_size = window_size
        self.alert_cooldown = alert_cooldown
        self.verbose = verbose
        
        # Source tracking for static log analysis
        self.source_packet_counts = defaultdict(int)
        self.source_byte_counts = defaultdict(int)
        self.source_timestamps = defaultdict(list)
        self.last_alert_time = defaultdict(lambda: datetime.min)
        
        print(f"[*] ICMP Flood Detector initialized")
        print(f"[*] Target IP: {target_ip or 'All IPs'}")
        print(f"[*] Detection threshold: {threshold} packets/sec")
        print(f"[*] Window size: {window_size} seconds")
        print(f"[*] Alert cooldown: {alert_cooldown} seconds")
    
    def parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime object."""
        if not timestamp_str:
            return datetime.now()
            
        try:
            # Try ISO format with timezone (Suricata default)
            if '+' in timestamp_str:
                # Handle timezone
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                # No timezone info
                dt = datetime.fromisoformat(timestamp_str)
            return dt
        except ValueError:
            try:
                # Try standard format
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                try:
                    # Try without microseconds
                    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    # Fall back to current time
                    return datetime.now()
    
    def check_for_flood(self, src_ip, dst_ip=None):
        """
        Check if the current packet rate for a source IP constitutes a flood attack.
        
        Args:
            src_ip: Source IP address to check
            dst_ip: Destination IP address (optional)
            
        Returns:
            Tuple of (is_attack, confidence, alert_data) if attack detected, None otherwise
        """
        # Skip if no packets
        if src_ip not in self.source_timestamps or len(self.source_timestamps[src_ip]) < 2:
            return None
            
        # Get timestamps and sort them
        timestamps = sorted(self.source_timestamps[src_ip])
        
        # Calculate time window
        time_diff = (timestamps[-1] - timestamps[0]).total_seconds()
        
        # Only check if we have at least 1 second of data
        if time_diff < 1.0:
            return None
            
        # Calculate packet rate
        packet_count = len(timestamps)
        packets_per_second = packet_count / time_diff
        
        if self.verbose:
            print(f"[DEBUG] Source: {src_ip}, Packets: {packet_count}, Time window: {time_diff:.2f}s, Rate: {packets_per_second:.2f} pps")
        
        # Check if this exceeds our threshold
        if packets_per_second >= self.threshold:
            # Calculate bytes per second
            bytes_per_second = self.source_byte_counts[src_ip] / time_diff
            
            return (True, 1.0, {
                'src_ip': src_ip,
                'dst_ip': dst_ip or "Unknown",
                'packets_per_second': packets_per_second,
                'bytes_per_second': bytes_per_second,
                'packet_count': packet_count,
                'time_window': time_diff
            })
        
        return None
    
    def process_suricata_eve(self, eve_json_line):
        """
        Process a line from Suricata's eve.json log file.
        
        Args:
            eve_json_line: A string containing a JSON line from eve.json
            
        Returns:
            Detection result if attack detected, None otherwise
        """
        try:
            # Parse the JSON line
            event = json.loads(eve_json_line)
            
            # Check if this is an ICMP event
            if 'proto' not in event or event['proto'] != 'ICMP':
                return None
                
            # Extract relevant fields
            timestamp_str = event.get('timestamp', datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
            timestamp = self.parse_timestamp(timestamp_str)
            src_ip = event.get('src_ip', '')
            dst_ip = event.get('dest_ip', '')
            
            # Skip if not targeting our monitored IP (if specified)
            if self.target_ip and dst_ip != self.target_ip:
                return None
                
            # Extract packet size if available, or use a default
            packet_size = 0
            if 'len' in event:
                packet_size = event['len']
            elif 'pkt_len' in event:  # This is used in the test_eve.json
                packet_size = event['pkt_len']
            elif 'packet_size' in event:
                packet_size = event['packet_size']
            else:
                packet_size = 64  # Default ICMP echo size
            
            if self.verbose:
                print(f"[DEBUG] ICMP packet: {src_ip} -> {dst_ip}, Size: {packet_size}, Time: {timestamp}")
            
            # Track this packet
            self.source_packet_counts[src_ip] += 1
            self.source_byte_counts[src_ip] += packet_size
            self.source_timestamps[src_ip].append(timestamp)
            
            # Check for flood attack
            return self.check_for_flood(src_ip, dst_ip)
            
        except json.JSONDecodeError:
            print(f"[!] Error parsing JSON line: {eve_json_line[:100]}...")
            return None
        except Exception as e:
            print(f"[!] Error processing Suricata event: {str(e)}")
            return None
    
    def send_email_alert(self, smtp_server, smtp_port, sender_email, 
                        sender_password, admin_email, alert_data):
        """
        Send an email alert when an ICMP flood is detected.
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP server port
            sender_email: Sender email address
            sender_password: Sender email password
            admin_email: Admin email address to send the alert to
            alert_data: Dictionary containing alert details
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = admin_email
            msg['Subject'] = f"ALERT: ICMP Flood Attack Detected from {alert_data['src_ip']}"
            
            # Create message body
            body = f"""
            ICMP Flood Attack Detected!
            
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Source IP: {alert_data['src_ip']}
            Target IP: {alert_data.get('dst_ip', 'Unknown')}
            
            Attack Details:
            - Packets per second: {alert_data['packets_per_second']:.2f}
            - Bytes per second: {alert_data['bytes_per_second']:.2f}
            - Packet count: {alert_data['packet_count']}
            - Time window: {alert_data.get('time_window', 0):.2f} seconds
            
            This alert was generated by the ICMP Flood Detection System.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server and send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
                
            print(f"[+] Email alert sent to {admin_email}")
            return True
            
        except Exception as e:
            print(f"[!] Error sending email alert: {str(e)}")
            return False


def monitor_eve_json(detector, eve_json_path, email_config=None, tail=False):
    """
    Monitor a Suricata eve.json file for ICMP flood attacks.
    
    Args:
        detector: ICMPFloodDetector instance
        eve_json_path: Path to the eve.json file
        email_config: Dictionary with email configuration
        tail: Whether to tail the file (keep reading new lines)
    """
    # Check if file exists
    if not os.path.exists(eve_json_path):
        print(f"[!] File not found: {eve_json_path}")
        return
    
    print(f"[*] Monitoring {eve_json_path} for ICMP flood attacks...")
    if tail:
        print("[*] Running in tail mode (press Ctrl+C to stop)")
        
    # Open the file
    with open(eve_json_path, 'r') as f:
        # Go to the end of the file if tailing
        if tail:
            f.seek(0, 2)  # Go to the end
            
        # Process lines
        line_count = 0
        icmp_count = 0
        
        # Track sources for periodic checking
        source_ips = set()
        last_check_time = time.time()
        check_interval = 1.0  # Check every second
        
        while True:
            line = f.readline()
            
            # If line is empty and we're not tailing, break
            if not line and not tail:
                break
                
            # If line is empty and we're tailing, wait for more data
            if not line and tail:
                time.sleep(0.1)
                
                # Periodically check all sources for flood attacks
                current_time = time.time()
                if current_time - last_check_time >= check_interval:
                    for src_ip in list(source_ips):
                        result = detector.check_for_flood(src_ip)
                        if result and result[0]:
                            is_attack, confidence, alert_data = result
                            print(f"\n[PERIODIC-CHECK] ICMP Flood Detected from {alert_data['src_ip']}")
                            print(f"          Packets/sec: {alert_data['packets_per_second']:.2f}")
                            print(f"          Packet count: {alert_data['packet_count']}")
                            print(f"          Time window: {alert_data.get('time_window', 0):.2f} seconds")
                            
                            # Send email alert if configured
                            if email_config:
                                detector.send_email_alert(
                                    email_config['smtp_server'],
                                    email_config['smtp_port'],
                                    email_config['sender_email'],
                                    email_config['sender_password'],
                                    email_config['admin_email'],
                                    alert_data
                                )
                    
                    last_check_time = current_time
                
                continue
            
            line_count += 1
            if line_count % 1000 == 0:
                print(f"[*] Processed {line_count} lines, found {icmp_count} ICMP packets")
                
            # Check if this is an ICMP packet before full processing
            if '"proto":"ICMP"' in line:
                icmp_count += 1
                
                try:
                    # Quick extraction of source IP for tracking
                    event = json.loads(line)
                    if 'src_ip' in event:
                        source_ips.add(event['src_ip'])
                except:
                    pass
                
                # Process the line
                result = detector.process_suricata_eve(line)
                
                # If attack detected, alert
                if result and result[0]:
                    is_attack, confidence, alert_data = result
                    print(f"\n[ALERT] ICMP Flood Detected from {alert_data['src_ip']} to {alert_data.get('dst_ip', 'Unknown')}")
                    print(f"          Packets/sec: {alert_data['packets_per_second']:.2f}")
                    print(f"          Bytes/sec: {alert_data['bytes_per_second']:.2f}")
                    print(f"          Packet count: {alert_data['packet_count']}")
                    print(f"          Time window: {alert_data.get('time_window', 0):.2f} seconds")
                    
                    # Send email alert if configured
                    if email_config:
                        detector.send_email_alert(
                            email_config['smtp_server'],
                            email_config['smtp_port'],
                            email_config['sender_email'],
                            email_config['sender_password'],
                            email_config['admin_email'],
                            alert_data
                        )
        
        # After processing all lines, check all sources for flood attacks
        if not tail:
            print("\n[*] Final check for ICMP flood attacks...")
            for src_ip in list(source_ips):
                result = detector.check_for_flood(src_ip)
                if result and result[0]:
                    is_attack, confidence, alert_data = result
                    print(f"\n[FINAL-CHECK] ICMP Flood Detected from {alert_data['src_ip']} to {alert_data.get('dst_ip', 'Unknown')}")
                    print(f"          Packets/sec: {alert_data['packets_per_second']:.2f}")
                    print(f"          Bytes/sec: {alert_data['bytes_per_second']:.2f}")
                    print(f"          Packet count: {alert_data['packet_count']}")
                    print(f"          Time window: {alert_data.get('time_window', 0):.2f} seconds")
                    
                    # Send email alert if configured
                    if email_config:
                        detector.send_email_alert(
                            email_config['smtp_server'],
                            email_config['smtp_port'],
                            email_config['sender_email'],
                            email_config['sender_password'],
                            email_config['admin_email'],
                            alert_data
                        )


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='ICMP Flood Detection System for Suricata')
    parser.add_argument('--model', default='model/icmp_flood_detector_model.pkl',
                        help='Path to the trained model pickle file')
    parser.add_argument('--scaler', default='model/scaler.pkl',
                        help='Path to the feature scaler pickle file')
    parser.add_argument('--eve-json', default='/var/log/suricata/eve.json',
                        help='Path to Suricata eve.json log file')
    parser.add_argument('--target-ip', default=None,
                        help='Target IP to monitor (default: monitor all)')
    parser.add_argument('--threshold', type=float, default=10.0,
                        help='Packets per second threshold for detection')
    parser.add_argument('--window', type=int, default=5,
                        help='Time window in seconds for traffic aggregation')
    parser.add_argument('--cooldown', type=int, default=60,
                        help='Alert cooldown period in seconds')
    parser.add_argument('--tail', action='store_true',
                        help='Continuously monitor the eve.json file (tail mode)')
    parser.add_argument('--email', action='store_true',
                        help='Enable email alerts')
    parser.add_argument('--smtp-server', default='smtp.gmail.com',
                        help='SMTP server for email alerts')
    parser.add_argument('--smtp-port', type=int, default=587,
                        help='SMTP port for email alerts')
    parser.add_argument('--sender-email', default='blackhatcys@gmail.com',
                        help='Sender email address')
    parser.add_argument('--sender-password', default='xpdd kbqv vyol msjd',
                        help='Sender email password')
    parser.add_argument('--admin-email', default='mohamed230104326@sut.edu.eg',
                        help='Admin email address to send alerts to')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose debug output')
    
    args = parser.parse_args()
    
    # Create detector
    detector = ICMPFloodDetector(
        model_path=args.model,
        scaler_path=args.scaler,
        target_ip=args.target_ip,
        threshold=args.threshold,
        window_size=args.window,
        alert_cooldown=args.cooldown,
        verbose=args.verbose
    )
    
    # Email configuration
    email_config = None
    if args.email:
        email_config = {
            'smtp_server': args.smtp_server,
            'smtp_port': args.smtp_port,
            'sender_email': args.sender_email,
            'sender_password': args.sender_password,
            'admin_email': args.admin_email
        }
        
        # Validate email config
        if not all([args.sender_email, args.sender_password, args.admin_email]):
            print("[!] Email alerts enabled but configuration incomplete")
            print("    Please provide --sender-email, --sender-password, and --admin-email")
            email_config = None
        else:
            print(f"[*] Email alerts will be sent to {args.admin_email}")
    
    # Monitor eve.json
    try:
        monitor_eve_json(detector, args.eve_json, email_config, args.tail)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")
    except Exception as e:
        print(f"[!] Error: {str(e)}")


if __name__ == "__main__":
    main()
