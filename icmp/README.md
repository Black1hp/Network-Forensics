# ICMP Flood (Ping Flood) Detector

This package provides a machine learning-based ICMP flood detection system that can be integrated with Suricata or used standalone. It detects ICMP flood attacks by analyzing network traffic patterns and can send email alerts to administrators when attacks are detected.

## Overview

ICMP flood (Ping flood) attacks are a type of Denial of Service (DoS) attack where an attacker overwhelms a target with ICMP echo request (ping) packets, causing degradation of service for legitimate users. This detector uses a Random Forest classifier trained on network traffic features to identify such attacks.

## Features

- Real-time detection of ICMP flood attacks
- Integration with Suricata's EVE JSON logs
- Email alerting capability
- Configurable detection thresholds and time windows
- Test mode for validation with sample data

## Directory Structure

```
icmp_flood_detector/
├── data/                      # Dataset directory
│   ├── icmp_traffic_dataset.csv       # Training dataset
│   └── icmp_traffic_test_dataset.csv  # Test dataset
├── model/                     # Trained model files
│   ├── icmp_flood_detector_model.pkl  # Random Forest model
│   └── scaler.pkl                     # Feature scaler
└── src/                       # Source code
    ├── create_synthetic_dataset.py    # Dataset generation script
    ├── train_model.py                 # Model training script
    └── icmp_flood_detector.py         # Detection module
```

## Installation

1. Clone this repository to your server
2. Ensure Python 3.6+ is installed
3. Install required dependencies:

```bash
pip install pandas numpy scikit-learn joblib
```

## Usage

### Running the Detector with Suricata

To monitor Suricata's EVE JSON log for ICMP flood attacks:

```bash
python src/icmp_flood_detector.py --eve-json /path/to/eve.json --tail
```

### Email Alerts

To enable email alerts:

```bash
python src/icmp_flood_detector.py --eve-json /path/to/eve.json --tail --email \
  --smtp-server smtp.gmail.com --smtp-port 587 \
  --sender-email your-email@gmail.com --sender-password your-password \
  --admin-email admin@example.com
```

### Configuration Options

- `--model`: Path to the trained model file (default: `../model/icmp_flood_detector_model.pkl`)
- `--scaler`: Path to the feature scaler file (default: `../model/scaler.pkl`)
- `--eve-json`: Path to Suricata's EVE JSON log (default: `/var/log/suricata/eve.json`)
- `--target-ip`: Target IP to monitor (default: monitor all IPs)
- `--threshold`: Packets per second threshold for detection (default: 10.0)
- `--window`: Time window in seconds for traffic aggregation (default: 5)
- `--cooldown`: Alert cooldown period in seconds (default: 300)
- `--tail`: Continuously monitor the EVE JSON file (tail mode)
- `--test`: Run in test mode with sample data

### Integration with Network-Forensics Project

To integrate with the Network-Forensics project:

1. Copy the `model` directory to `/backend/ml_icmp_flood_detector/`
2. Copy the `src/icmp_flood_detector.py` file to `/backend/ml_icmp_flood_detector/`
3. Update your `.env` file with the following:

```
ICMP_ML_MODEL_FILENAME="ml_icmp_flood_detector/icmp_flood_detector_model.pkl"
ICMP_ML_SCALER_FILENAME="ml_icmp_flood_detector/scaler.pkl"
```

4. Modify the `server.py` file to import and initialize the ICMP flood detector in a background thread, similar to the port scan detector integration.

## Dataset Information

The model was trained on a synthetic dataset inspired by the CIC-DDoS2019 dataset from the Canadian Institute for Cybersecurity. The dataset contains both normal ICMP traffic and ICMP flood attack patterns.

Key features used for detection:
- Packet size
- Packets per second
- Bytes per second
- ICMP type
- ICMP code

## Model Performance

The Random Forest classifier achieves high accuracy in distinguishing between normal ICMP traffic and flood attacks. Feature importance analysis shows that traffic volume metrics (packets per second and bytes per second) are the most significant indicators of an attack.

## License

This project is provided for educational and defensive security purposes only.

## References

- CIC-DDoS2019 dataset: https://www.unb.ca/cic/datasets/ddos-2019.html
- Suricata IDS: https://suricata.io/
