#!/usr/bin/env python3
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
print("\nSource IP Analysis:")
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
