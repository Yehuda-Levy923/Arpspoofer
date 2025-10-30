# Arpspoofer

Lightweight Python ARP spoofing/poisoning utility.

> Simple, single-file ARP spoof tool intended for network testing and learning.

## Features
- Performs ARP spoofing between a target and gateway
- Minimal dependencies
- Designed for quick testing in controlled environments

## Requirements
- Python 3.8+
- Root/administrator privileges (required to send raw packets)
- scapy (or other packet library if used in the script)

Install dependencies (example):
```bash
pip install -r requirements.txt
# or
pip install scapy
```

## Usage
Run as root on a machine within the target network:

```bash
sudo python3 arpspoofer.py -i \Device\NPF_{7D164A2A-DA9F-4FC6-B87E-AE02AC2F342B} -s 10.7.15.254 -gw -d 0.1 -t 10.7.8.20
```

Replace <target-ip> and <gateway-ip> with the IP addresses you want to poison between.

Stop the script with Ctrl+C. If the script supports restoration, it will attempt to restore ARP tables on exit.

## Warning & Ethics
ARP spoofing can disrupt networks and enable interception of traffic. Only use this tool:
- On networks you own or have explicit permission to test
- For legitimate security testing, education, or research

Unauthorized use may be illegal.

## Contributing
Small repo — feel free to open issues or PRs for fixes, documentation improvements, or dependency updates.
