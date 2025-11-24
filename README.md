# Arpspoofer

Lightweight Python ARP spoofing/poisoning utility.

> Simple, single-file ARP spoof tool intended for network testing and learning.

This repository contains two related tools:
- arpspoofer — a small ARP spoofing/poisoning utility used to inject spoofed ARP responses between a target and a gateway for testing and learning.
- arpdetector — a companion passive detector that monitors ARP traffic and raises alerts when suspicious or inconsistent ARP activity is observed (useful when testing arpspoofer in a controlled environment).

## Features

arpspoofer
- Performs ARP spoofing/poisoning between a target and gateway
- Minimal dependencies and single-file deployment
- Designed for quick testing in controlled environments

arpdetector
- Passive ARP monitor that inspects ARP replies and requests on an interface
- Detects conflicting ARP bindings and multiple MACs for the same IP
- Logs alerts and optionally prints detailed packet information for analysis
- Minimal dependencies, intended for quick observation and validation during tests

## Requirements
- Python 3.8+
- Root/administrator privileges (required to send/receive raw packets)
- scapy (or similar packet library used by the scripts)

Install dependencies (example):
```bash
pip install -r requirements.txt
# or
pip install scapy
```

## Usage

General note: Always run these tools only on networks you own or where you have explicit permission to test.

arpspoofer
Run as root on a machine within the target network:

```bash
sudo python3 arpspoofer.py -i <interface> -s <gateway-ip> -t <target-ip> -d <delay>
```

Example:
```bash
sudo python3 arpspoofer.py -i \Device\NPF_{7D164A2A-DA9F-4FC6-B87E-AE02AC2F342B} -s 10.7.15.254 -t 10.7.8.20 -d 0.1
```

Replace <target-ip> and <gateway-ip> with the IP addresses you want to poison between. Stop the script with Ctrl+C.
# Arpdetector
Run as root to listen for ARP traffic on an interface and report suspicious activity. Use the script's built-in help to see available options:

Typical invocation:
```bash
sudo python3 arpdetector.py
```

What arpdetector helps with:
- Observe ARP replies and requests in real time
- Identify when a single IP starts appearing with multiple different MAC addresses
- Provide timestamps and packet details for incident analysis
- Act as a baseline detector when testing arpspoofer in a lab

If the detector has CLI options, use --help to view them and tailor logging/verbosity/thresholds to your environment.

## Combining arpspoofer and arpdetector
For safe testing, run arpdetector on a monitoring host (or the same host in a separate terminal) while you run arpspoofer to verify the spoofing behavior and confirm that the detector flags the expected anomalies. This is useful for learning how ARP poisoning manifests on the wire and validating detection logic.

## Logging & Troubleshooting
- If you see no output, verify you are running the script as root and that the selected interface is up.
- Use packet capture tools (tcpdump/wireshark) to cross-check ARP traffic when troubleshooting.
- Consult each script's --help or top-of-file comments for detailed usage and options.

## Contributing
Small repo — feel free to open issues or PRs for:
- Fixes and bug reports
- Documentation improvements
- Adding tests or CI
- Improving the detector’s heuristics and reducing false positives
## Contact
If you have questions or suggestions, open an issue or submit a pull request in this repository.
```
