#!/usr/bin/env python3
"""
Debug script for ICMP flood detector with minimal test case.

This script creates a minimal test case with a clear ICMP flood pattern
and runs the detector with extensive debug output to identify issues.
"""

import os
import json
import time
from datetime import datetime, timedelta
import random
import subprocess

def create_minimal_test_case(filename):
    """Create a minimal test case with clear ICMP flood pattern."""
    # Create a base timestamp
    base_time = datetime.now()
    
    # Create events list
    events = []
    
    # Add some normal traffic from different IPs
    for i in range(10):
        src_ip = f"192.168.1.{i+10}"
        timestamp = base_time + timedelta(seconds=i*5)  # 5 seconds apart
        
        event = {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0300",
            "flow_id": random.randint(1000000000000000, 9999999999999999),
            "in_iface": "ens33",
            "event_type": "flow",
            "src_ip": src_ip,
            "src_port": 0,
            "dest_ip": "192.168.1.1",
            "dest_port": 0,
            "proto": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "pkt_len": 64,
            "community_id": f"1:{random.randint(10000000, 99999999)}="
        }
        events.append(event)
    
    # Add a clear flood pattern from a single IP
    attack_src = "45.123.45.67"
    attack_packets = 50  # 50 packets
    attack_interval = 0.1  # 0.1 seconds between packets = 10 packets per second
    
    for i in range(attack_packets):
        timestamp = base_time + timedelta(seconds=60 + i * attack_interval)  # Start at 60s mark
        
        event = {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0300",
            "flow_id": random.randint(1000000000000000, 9999999999999999),
            "in_iface": "ens33",
            "event_type": "flow",
            "src_ip": attack_src,
            "src_port": 0,
            "dest_ip": "192.168.1.1",
            "dest_port": 0,
            "proto": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "pkt_len": 64,
            "community_id": f"1:{random.randint(10000000, 99999999)}="
        }
        events.append(event)
    
    # Write events to file
    with open(filename, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    print(f"Created minimal test case at {filename}")
    print(f"Normal ICMP events: 10")
    print(f"Attack ICMP events: {attack_packets} (from {attack_src} at 10 packets/second)")
    
    return attack_src

def run_detector_with_debug(eve_json_path, detector_script):
    """Run the detector with extensive debug output."""
    # Create a modified version of the detector with extra debug output
    debug_detector = detector_script.replace('.py', '_debug.py')
    
    with open(detector_script, 'r') as f:
        code = f.read()
    
    # Add more debug prints
    debug_code = code.replace(
        'if self.verbose:',
        'if True:'  # Always print debug info
    )
    
    with open(debug_detector, 'w') as f:
        f.write(debug_code)
    
    # Run the detector with debug output
    cmd = [
        "python3", 
        debug_detector, 
        "--eve-json", eve_json_path,
        "--threshold", "5",  # Should detect 10 packets/second
        "--window", "2",
        "--verbose"
    ]
    
    print("\nRunning detector with debug output...")
    print(f"Command: {' '.join(cmd)}")
    print("\nDetector output:")
    print("-" * 50)
    
    process = subprocess.run(cmd, capture_output=True, text=True)
    print(process.stdout)
    
    if process.stderr:
        print("Errors:")
        print(process.stderr)
    
    # Clean up
    os.remove(debug_detector)
    
    return "ICMP Flood Detected" in process.stdout or "Possible ICMP Flood" in process.stdout

def main():
    # Create test directory if it doesn't exist
    test_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test')
    os.makedirs(test_dir, exist_ok=True)
    
    # Path to minimal test case
    eve_json_path = os.path.join(test_dir, 'minimal_test.json')
    
    # Path to detector script
    detector_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icmp_flood_detector_suricata.py')
    
    # Create minimal test case
    attack_src = create_minimal_test_case(eve_json_path)
    
    # Run detector with debug output
    detected = run_detector_with_debug(eve_json_path, detector_script)
    
    # Print results
    print("\nTest Results:")
    print("-" * 50)
    if detected:
        print("✅ SUCCESS: ICMP flood attack was detected!")
    else:
        print("❌ FAILURE: ICMP flood attack was not detected.")
    
    print(f"Attack source: {attack_src}")
    print(f"Test file: {eve_json_path}")
    
    # Create a simple Python script to directly analyze the test file
    direct_analysis_script = os.path.join(test_dir, 'analyze_test.py')
    with open(direct_analysis_script, 'w') as f:
        f.write("""#!/usr/bin/env python3
import json
import sys
from collections import defaultdict
from datetime import datetime

def parse_timestamp(ts_str):
    try:
        if '+' in ts_str:
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        else:
            return datetime.fromisoformat(ts_str)
    except ValueError:
        try:
            return datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            try:
                return datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return datetime.now()

# Read the test file
with open(sys.argv[1], 'r') as f:
    lines = f.readlines()

# Count packets per source IP
src_packets = defaultdict(list)

for line in lines:
    try:
        event = json.loads(line)
        if event.get('proto') == 'ICMP':
            src_ip = event.get('src_ip')
            timestamp = parse_timestamp(event.get('timestamp'))
            src_packets[src_ip].append(timestamp)
    except:
        pass

# Analyze packet rates
print("\\nSource IP Analysis:")
print("-" * 50)
for src_ip, timestamps in src_packets.items():
    if len(timestamps) < 2:
        continue
        
    timestamps.sort()
    time_diff = (timestamps[-1] - timestamps[0]).total_seconds()
    if time_diff > 0:
        rate = len(timestamps) / time_diff
        print(f"Source: {src_ip}, Packets: {len(timestamps)}, Time window: {time_diff:.2f}s, Rate: {rate:.2f} packets/sec")
        
        # Print first few timestamps to verify
        print(f"  First timestamp: {timestamps[0]}")
        print(f"  Last timestamp: {timestamps[-1]}")
""")
    
    # Make it executable
    os.chmod(direct_analysis_script, 0o755)
    
    # Run the analysis script
    print("\nRunning direct analysis of test file...")
    subprocess.run(['python3', direct_analysis_script, eve_json_path])

if __name__ == "__main__":
    main()
