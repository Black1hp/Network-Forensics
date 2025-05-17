#!/usr/bin/env python3
"""
Test script for validating the ICMP flood detector with sample Suricata eve.json data.

This script creates a synthetic eve.json file with ICMP flood patterns and tests
the detector's ability to identify these patterns correctly.
"""

import os
import json
import time
from datetime import datetime, timedelta
import random
import subprocess

def generate_normal_icmp_event(src_ip, dst_ip, timestamp=None):
    """Generate a normal ICMP event in Suricata eve.json format."""
    if timestamp is None:
        timestamp = datetime.now()
    
    return {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0300",
        "flow_id": random.randint(1000000000000000, 9999999999999999),
        "in_iface": "ens33",
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": 0,
        "dest_ip": dst_ip,
        "dest_port": 0,
        "proto": "ICMP",
        "icmp_type": 8,
        "icmp_code": 0,
        "pkt_len": random.randint(64, 1500),
        "community_id": f"1:{random.randint(10000000, 99999999)}="
    }

def generate_flood_icmp_events(src_ip, dst_ip, count=100, interval_ms=10):
    """Generate a series of ICMP events that constitute a flood attack."""
    events = []
    base_time = datetime.now()
    
    for i in range(count):
        timestamp = base_time + timedelta(milliseconds=i * interval_ms)
        event = generate_normal_icmp_event(src_ip, dst_ip, timestamp)
        events.append(event)
    
    return events

def create_test_eve_json(filename, normal_count=50, attack_count=100):
    """Create a test eve.json file with normal and attack ICMP traffic."""
    events = []
    
    # Generate normal ICMP traffic from various sources
    for i in range(normal_count):
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        dst_ip = "192.168.1.1"
        events.append(generate_normal_icmp_event(src_ip, dst_ip))
        time.sleep(0.01)  # Small delay to ensure different timestamps
    
    # Generate ICMP flood from a single source
    attack_src = f"45.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    attack_dst = "192.168.1.1"
    flood_events = generate_flood_icmp_events(attack_src, attack_dst, attack_count)
    events.extend(flood_events)
    
    # Write events to file
    with open(filename, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    print(f"Created test eve.json file at {filename}")
    print(f"Normal ICMP events: {normal_count}")
    print(f"Attack ICMP events: {attack_count} (from {attack_src} to {attack_dst})")
    
    return attack_src, attack_dst

def test_detector(eve_json_path, detector_script):
    """Test the ICMP flood detector with the generated eve.json file."""
    cmd = [
        "python3", 
        detector_script, 
        "--eve-json", eve_json_path,
        "--threshold", "5",  # Lower threshold for testing
        "--window", "2",     # Smaller window for testing
        "--verbose"
    ]
    
    print("\nTesting ICMP flood detector...")
    print(f"Command: {' '.join(cmd)}")
    print("\nDetector output:")
    print("-" * 50)
    
    process = subprocess.run(cmd, capture_output=True, text=True)
    print(process.stdout)
    
    if process.stderr:
        print("Errors:")
        print(process.stderr)
    
    return "ICMP Flood Detected" in process.stdout or "Possible ICMP Flood" in process.stdout

def main():
    # Create test directory if it doesn't exist
    test_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test')
    os.makedirs(test_dir, exist_ok=True)
    
    # Path to test eve.json file
    eve_json_path = os.path.join(test_dir, 'test_eve.json')
    
    # Path to detector script
    detector_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icmp_flood_detector_suricata.py')
    
    # Create test eve.json file with more concentrated attack
    attack_src, attack_dst = create_test_eve_json(eve_json_path, normal_count=20, attack_count=200)
    
    # Test the detector
    detected = test_detector(eve_json_path, detector_script)
    
    # Print results
    print("\nTest Results:")
    print("-" * 50)
    if detected:
        print("✅ SUCCESS: ICMP flood attack was detected!")
    else:
        print("❌ FAILURE: ICMP flood attack was not detected.")
    
    print(f"Attack source: {attack_src}")
    print(f"Attack target: {attack_dst}")
    print(f"Test eve.json: {eve_json_path}")

if __name__ == "__main__":
    main()
