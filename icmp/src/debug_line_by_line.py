#!/usr/bin/env python3
"""
Line-by-line debugging script for ICMP flood detection.

This script reads a Suricata eve.json file line by line and performs
detailed debugging of the ICMP flood detection logic, printing the
full state after each line to identify where detection fails.
"""

import os
import sys
import json
from datetime import datetime, timedelta
from collections import defaultdict

def parse_timestamp(timestamp_str):
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

def debug_icmp_flood_detection(eve_json_path, threshold=5.0):
    """
    Debug ICMP flood detection logic line by line.
    
    Args:
        eve_json_path: Path to the eve.json file
        threshold: Packets per second threshold for detection
    """
    # Check if file exists
    if not os.path.exists(eve_json_path):
        print(f"[!] File not found: {eve_json_path}")
        return
    
    print(f"[*] Starting line-by-line debug of {eve_json_path}")
    print(f"[*] Detection threshold: {threshold} packets/sec")
    
    # Source tracking
    source_packets = defaultdict(list)  # src_ip -> [(timestamp, size), ...]
    
    # Open the file
    with open(eve_json_path, 'r') as f:
        line_count = 0
        icmp_count = 0
        
        # Process lines
        for line in f:
            line_count += 1
            
            # Print every 10th line to show progress
            if line_count % 10 == 0:
                print(f"Processing line #{line_count}...")
            
            try:
                # Parse the JSON line
                event = json.loads(line)
                
                # Check if this is an ICMP packet - proper JSON parsing
                if event.get('proto') != 'ICMP':
                    continue
                    
                icmp_count += 1
                print(f"\n--- Processing ICMP packet #{icmp_count} (line #{line_count}) ---")
                
                # Extract relevant fields
                timestamp_str = event.get('timestamp', datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
                timestamp = parse_timestamp(timestamp_str)
                src_ip = event.get('src_ip', '')
                dst_ip = event.get('dest_ip', '')
                
                # Extract packet size
                packet_size = 0
                if 'len' in event:
                    packet_size = event['len']
                elif 'pkt_len' in event:
                    packet_size = event['pkt_len']
                elif 'packet_size' in event:
                    packet_size = event['packet_size']
                else:
                    packet_size = 64  # Default ICMP echo size
                
                print(f"Packet: {src_ip} -> {dst_ip}, Size: {packet_size}, Time: {timestamp}")
                
                # Add packet to tracking
                source_packets[src_ip].append((timestamp, packet_size))
                
                # Calculate packet rate
                packets = source_packets[src_ip]
                print(f"Source {src_ip} now has {len(packets)} packets")
                
                if len(packets) >= 2:
                    # Sort packets by timestamp
                    packets.sort(key=lambda x: x[0])
                    
                    # Calculate time window
                    time_diff = (packets[-1][0] - packets[0][0]).total_seconds()
                    
                    # Calculate packet rate
                    packet_count = len(packets)
                    packets_per_second = packet_count / time_diff if time_diff > 0 else 0
                    
                    print(f"Time window: {time_diff:.2f}s, Rate: {packets_per_second:.2f} packets/sec")
                    print(f"First packet: {packets[0][0]}")
                    print(f"Last packet: {packets[-1][0]}")
                    
                    # Check if this exceeds our threshold
                    if packets_per_second >= threshold and time_diff >= 1.0:
                        print(f"*** DETECTION TRIGGERED: Rate {packets_per_second:.2f} exceeds threshold {threshold} ***")
                        
                        # Calculate bytes per second
                        total_bytes = sum(size for _, size in packets)
                        bytes_per_second = total_bytes / time_diff
                        
                        print(f"Bytes/sec: {bytes_per_second:.2f}")
                    else:
                        if packets_per_second < threshold:
                            print(f"Rate {packets_per_second:.2f} below threshold {threshold}")
                        if time_diff < 1.0:
                            print(f"Time window {time_diff:.2f}s too small (need >= 1.0s)")
                
            except json.JSONDecodeError:
                print(f"[!] Error parsing JSON line: {line[:100]}...")
            except Exception as e:
                print(f"[!] Error processing line: {str(e)}")
    
    # Final analysis
    print("\n=== Final Analysis ===")
    print(f"Total lines processed: {line_count}")
    print(f"Total ICMP packets found: {icmp_count}")
    print(f"Unique source IPs: {len(source_packets)}")
    
    for src_ip, packets in source_packets.items():
        if len(packets) >= 2:
            packets.sort(key=lambda x: x[0])
            time_diff = (packets[-1][0] - packets[0][0]).total_seconds()
            if time_diff > 0:
                rate = len(packets) / time_diff
                print(f"Source: {src_ip}, Packets: {len(packets)}, Time window: {time_diff:.2f}s, Rate: {rate:.2f} packets/sec")
                print(f"  First timestamp: {packets[0][0]}")
                print(f"  Last timestamp: {packets[-1][0]}")
                
                if rate >= threshold and time_diff >= 1.0:
                    print(f"  *** DETECTION TRIGGERED: Rate {rate:.2f} exceeds threshold {threshold} ***")

def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_line_by_line.py <eve_json_path> [threshold]")
        return
    
    eve_json_path = sys.argv[1]
    threshold = 5.0
    
    if len(sys.argv) >= 3:
        try:
            threshold = float(sys.argv[2])
        except ValueError:
            print(f"Invalid threshold: {sys.argv[2]}, using default: {threshold}")
    
    debug_icmp_flood_detection(eve_json_path, threshold)

if __name__ == "__main__":
    main()
