# Network Forensics IDS Project

This project is an Intrusion Detection System (IDS) designed to detect various network attacks including Port Scanning, ICMP Flooding, and DDoS attacks. The system integrates Suricata with custom detection modules and provides a web-based dashboard for monitoring and alerts.

## Features

- **Port Scan Detection**: Uses machine learning to identify port scanning activities
- **ICMP Flood Detection**: Detects ICMP flood attacks through traffic analysis
- **Suricata Integration**: Leverages Suricata's powerful detection capabilities
- **Real-time Alerts**: Email notifications for detected threats
- **Web Dashboard**: React-based frontend for monitoring system status and alerts

## Prerequisites

- Python 3.8+
- Node.js 14+
- npm or yarn
- Suricata (optional, for full functionality)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/Network-Forensics.git
   cd Network-Forensics
   ```

2. Install backend dependencies:
   ```
   pip install -r backend/requirements.txt
   ```

3. Install frontend dependencies:
   ```
   cd frontend
   npm install
   cd ..
   ```

4. Configure environment variables:
   - Copy the `.env.example` file to `.env`
   - Update the values in `.env` to match your environment

## Usage

### Starting the IDS

The project has been integrated to run with minimal terminal usage. Simply use:

```
./start.sh
```

This script will:
1. Start the backend Flask server
2. Start the Suricata integration module
3. Start the React frontend development server
4. Log all output to the `logs` directory

### Stopping the IDS

To stop all components:

```
./stop.sh
```

### Manual Component Execution (if needed)

If you need to run components individually:

1. Backend Server:
   ```
   python backend/server.py
   ```

2. Suricata Integration:
   ```
   python backend/suricata_integration.py
   ```

3. Frontend:
   ```
   cd frontend
   npm run dev
   ```

## Project Structure

```
Network-Forensics/
├── .env                    # Environment configuration
├── test_eve.json          # Test data for Suricata
├── start.sh               # Script to start all components
├── stop.sh                # Script to stop all components
├── backend/
│   ├── server.py          # Main Flask server
│   ├── suricata_integration.py  # Suricata integration
│   ├── suricata.yaml      # Suricata configuration
│   ├── requirements.txt   # Python dependencies
│   ├── ml_port_scan_detector/  # Port scan detection module
│   │   ├── ml_portscan_detector.py
│   │   ├── portscan_detector_model.pkl
│   │   └── scaler.pkl
│   └── icmp_detector/     # ICMP flood detection module
│       └── icmp_flood_detector_final.py
└── frontend/              # React frontend application
    ├── src/               # Source code
    ├── package.json       # Node.js dependencies
    └── ...                # Other frontend configuration files
```

## Testing Attacks

### Port Scanning Test

You can test port scanning detection using tools like nmap:

```
nmap -p 1-1000 [target_ip]
```

### ICMP Flood Test

To test ICMP flood detection:

```
ping -f [target_ip]
```

## Troubleshooting

- Check the log files in the `logs` directory for error messages
- Ensure all required ports are available (default: 3000 for frontend, 5000 for backend)
- Verify that the `.env` file contains correct configuration values

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
