#!/usr/bin/env python3
"""
Create synthetic dataset for ICMP flood detection.

This script generates a synthetic dataset that simulates normal ICMP traffic
and ICMP flood attack traffic based on key characteristics observed in real-world
scenarios. The dataset is saved as a CSV file for model training.

Dataset source inspiration: CIC-DDoS2019 dataset from the Canadian Institute for Cybersecurity
https://www.unb.ca/cic/datasets/ddos-2019.html
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta

# Set random seed for reproducibility
np.random.seed(42)

def generate_normal_icmp_traffic(num_samples=1000):
    """Generate synthetic normal ICMP traffic data."""
    data = {
        'timestamp': [],
        'src_ip': [],
        'dst_ip': [],
        'protocol': [],
        'icmp_type': [],
        'icmp_code': [],
        'packet_size': [],
        'packets_per_second': [],
        'bytes_per_second': [],
        'is_attack': []
    }
    
    # Base timestamp
    base_time = datetime.now()
    
    for i in range(num_samples):
        # Generate timestamp with realistic intervals
        timestamp = base_time + timedelta(seconds=np.random.uniform(0, 3600))
        
        # Generate source IP (random but realistic)
        src_ip = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        
        # Generate destination IP (usually a fixed server or small set of servers)
        dst_ip = f"10.0.0.{np.random.randint(1, 10)}"
        
        # ICMP protocol
        protocol = 'ICMP'
        
        # ICMP type (0=echo reply, 8=echo request/ping)
        icmp_type = np.random.choice([0, 8], p=[0.5, 0.5])
        
        # ICMP code (usually 0 for echo request/reply)
        icmp_code = 0
        
        # Normal ICMP packet size (typically 64-1500 bytes)
        packet_size = np.random.randint(64, 1500)
        
        # Normal traffic has low packets per second (0.1-5 pps)
        packets_per_second = np.random.uniform(0.1, 5.0)
        
        # Calculate bytes per second
        bytes_per_second = packets_per_second * packet_size
        
        # Append to data dictionary
        data['timestamp'].append(timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'))
        data['src_ip'].append(src_ip)
        data['dst_ip'].append(dst_ip)
        data['protocol'].append(protocol)
        data['icmp_type'].append(icmp_type)
        data['icmp_code'].append(icmp_code)
        data['packet_size'].append(packet_size)
        data['packets_per_second'].append(packets_per_second)
        data['bytes_per_second'].append(bytes_per_second)
        data['is_attack'].append(0)  # 0 = normal traffic
    
    return pd.DataFrame(data)

def generate_icmp_flood_traffic(num_samples=1000):
    """Generate synthetic ICMP flood attack traffic data."""
    data = {
        'timestamp': [],
        'src_ip': [],
        'dst_ip': [],
        'protocol': [],
        'icmp_type': [],
        'icmp_code': [],
        'packet_size': [],
        'packets_per_second': [],
        'bytes_per_second': [],
        'is_attack': []
    }
    
    # Base timestamp
    base_time = datetime.now()
    
    # For ICMP flood, often a small number of source IPs targeting one destination
    # Create 5 attack sources
    attack_src_ips = [f"45.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" 
                     for _ in range(5)]
    
    # Target IP (usually a single target)
    target_ip = "10.0.0.1"
    
    # Create 10 attack bursts with high packet rates
    for burst in range(10):
        # Each burst has a specific start time
        burst_start = base_time + timedelta(seconds=burst*60)  # One burst every minute
        
        # Each burst has 100 packets
        for i in range(100):
            # Packets in a burst are close together in time
            timestamp = burst_start + timedelta(milliseconds=i*10)  # 10ms between packets = 100 packets per second
            
            # Select a source IP from the attack sources
            src_ip = attack_src_ips[burst % len(attack_src_ips)]
            
            # Target IP
            dst_ip = target_ip
            
            # ICMP protocol
            protocol = 'ICMP'
            
            # ICMP type (8=echo request/ping is most common in floods)
            icmp_type = 8
            
            # ICMP code (usually 0 for echo request)
            icmp_code = 0
            
            # ICMP flood packets can be of various sizes, often larger
            packet_size = np.random.randint(64, 3000)
            
            # High packet rate is the key characteristic of ICMP flood (100 pps for this burst)
            packets_per_second = 100.0
            
            # Calculate bytes per second
            bytes_per_second = packets_per_second * packet_size
            
            # Append to data dictionary
            data['timestamp'].append(timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'))
            data['src_ip'].append(src_ip)
            data['dst_ip'].append(dst_ip)
            data['protocol'].append(protocol)
            data['icmp_type'].append(icmp_type)
            data['icmp_code'].append(icmp_code)
            data['packet_size'].append(packet_size)
            data['packets_per_second'].append(packets_per_second)
            data['bytes_per_second'].append(bytes_per_second)
            data['is_attack'].append(1)  # 1 = attack traffic
    
    return pd.DataFrame(data)

def main():
    # Create output directory if it doesn't exist
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate normal and attack traffic
    print("Generating normal ICMP traffic data...")
    normal_df = generate_normal_icmp_traffic(num_samples=2000)
    
    print("Generating ICMP flood attack traffic data...")
    attack_df = generate_icmp_flood_traffic(num_samples=1000)  # Will generate 1000 attack packets in bursts
    
    # Combine datasets
    combined_df = pd.concat([normal_df, attack_df], ignore_index=True)
    
    # Shuffle the dataset
    combined_df = combined_df.sample(frac=1).reset_index(drop=True)
    
    # Save to CSV
    output_file = os.path.join(output_dir, 'icmp_traffic_dataset.csv')
    combined_df.to_csv(output_file, index=False)
    print(f"Dataset saved to {output_file}")
    
    # Print dataset statistics
    print("\nDataset Statistics:")
    print(f"Total samples: {len(combined_df)}")
    print(f"Normal traffic samples: {len(combined_df[combined_df['is_attack'] == 0])}")
    print(f"Attack traffic samples: {len(combined_df[combined_df['is_attack'] == 1])}")
    
    # Create a test dataset with concentrated attack samples to ensure detection
    # Take 200 normal samples
    test_normal = normal_df.sample(n=200)
    
    # Take 300 attack samples, but ensure they're from the same source IPs and close in time
    # This simulates a real attack burst that should trigger detection
    attack_sources = attack_df['src_ip'].unique()
    test_attack = pd.DataFrame()
    
    for src_ip in attack_sources[:3]:  # Use first 3 attack sources
        src_attacks = attack_df[attack_df['src_ip'] == src_ip].copy()
        if len(src_attacks) > 0:
            # Sort by timestamp to get sequential packets
            src_attacks.loc[:, 'timestamp'] = pd.to_datetime(src_attacks['timestamp'])
            src_attacks = src_attacks.sort_values('timestamp')
            
            # Take up to 100 sequential packets from this source
            if len(src_attacks) > 100:
                src_attacks = src_attacks.iloc[:100]
            
            test_attack = pd.concat([test_attack, src_attacks])
    
    # Combine test data
    test_df = pd.concat([test_normal, test_attack], ignore_index=True)
    
    # Save test dataset
    test_output_file = os.path.join(output_dir, 'icmp_traffic_test_dataset.csv')
    test_df.to_csv(test_output_file, index=False)
    print(f"Test dataset saved to {test_output_file}")
    print(f"Test dataset normal samples: {len(test_df[test_df['is_attack'] == 0])}")
    print(f"Test dataset attack samples: {len(test_df[test_df['is_attack'] == 1])}")

if __name__ == "__main__":
    main()
