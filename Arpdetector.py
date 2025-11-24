from scapy.all import *
from scapy.layers.l2 import ARP
from datetime import datetime

interface = conf.iface        # Default interface to sniff on
DELAY = 1                     # Sniffing loop delay in seconds

arp_table = {}                 # Dictionary to store IP -> MAC observed mappings
unsolicited_count = 0          # Counter for unsolicited ARP replies/requests
conflict_count = 0             # Counter for conflicting ARP replies (same IP, different MAC)
INDICATORS_REQUIRED = 2        # Number of indicators required to trigger warning
times_printed = 0              # Tracks how many times we've printed unsolicited message (\100)


# --- Timestamp getter ---
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# --- Packet Handler ---
# This function is called for every ARP packet captured and checks for indicators of falsities
def handle_arp(pkt):
    global unsolicited_count, conflict_count, times_printed

    # Check if packet contains ARP layer, if not return early
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]        # Extract ARP layer from packet
    src_ip = arp.psrc     # Source IP address from ARP packet
    src_mac = arp.hwsrc   # Source MAC address from ARP packet
    op = arp.op           # Operation code for request/reply

    # --- Indicator 1: Conflicting MACs ---
    # Check if we've seen this IP before with a different MAC address
    # This indicates potential ARP spoofing (same IP claiming different MAC)
    if src_ip in arp_table and arp_table[src_ip] != src_mac:
        conflict_count += 1  # Increment conflict counter
        timestamp = get_timestamp()
        # Print conflict: shows old MAC -> new MAC for the same IP
        print(f"[{timestamp}] Conflict: {src_ip}: {arp_table[src_ip]} -> {src_mac}")

    # Save or update the IP -> MAC mapping in our table
    arp_table[src_ip] = src_mac

    # --- Indicator 2: Unsolicited ARP replies/requests ---
    # Check if this is an ARP reply (op=2) or request (op=1) where the target IP
    # doesn't match the source IP (indicating unsolicited/gratuitous ARP)
    if (op == 2 or op == 1) and arp.pdst != src_ip:
        unsolicited_count += 1  # Increment unsolicited counter
        # Only print every 100 unsolicited packets to avoid spam
        if unsolicited_count >= 100 * times_printed:
            times_printed += 1
            timestamp = get_timestamp()
            print(f"[{timestamp}] 100 Unsolicited: {src_ip} ({src_mac}) -> {arp.pdst}")

# --- Warning logic ---
# Checks if we have enough indicators to trigger a spoofing warning
def check_for_warning():
    global unsolicited_count, conflict_count

    indicators = 0  # Counter for how many types of suspicious activity detected

    # Check if we've seen any conflicting MAC addresses
    if conflict_count > 0:
        indicators += 1

    # Check if we've seen any unsolicited ARP packets
    if unsolicited_count > 0:
        indicators += 1

    # If we have enough indicators, print warning and reset counters
    if indicators >= INDICATORS_REQUIRED:
        timestamp = get_timestamp()
        print(f"\n[{timestamp}] !!! WARNING !!!")
        print("ARP Spoofing detected!!!!!")
        print(f"Conflicts: {conflict_count}")
        print(f"Unsolicited Replies/Requests: {unsolicited_count}\n")

        # Reset indicator counters after warning is issued
        unsolicited_count = 0
        conflict_count = 0

        return True

    return False


# --- Main Loop ---
if __name__ == "__main__":
    start_time = get_timestamp()  # Get and print start time
    print(f"[{start_time}]\n Starting ARP spoofing warning system")
    print("Waiting for ARP activity...\n")

    # Infinite loop to continuously monitor ARP traffic
    while True:
        # Sniff ARP packets on the specified interface
        sniff(filter="arp",      # only capture ARP packets
              iface=interface,   # interface to sniff on
              prn=handle_arp,    # function to call for each packet
              store=False,       # don't store packets in memory
              timeout=DELAY)     # sniff for DELAY seconds before checking warnings

        # After each sniffing interval, check if we should issue a warning
        check_for_warning()