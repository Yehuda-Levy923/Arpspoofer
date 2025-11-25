from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from datetime import datetime

interface = conf.iface                  # Default interface to sniff on
gw_ip = conf.route.route("0.0.0.0")[2]  # Default gateway IP address
my_mac = get_if_hwaddr(interface)       # My own MAC address
DELAY = 1                               # Sniffing loop delay in seconds

arp_table = {}                          # Dictionary to store IP -> MAC observed mappings
unsolicited_count = 0                   # Counter for unsolicited ARP replies/requests
conflict_count = 0                      # Counter for conflicting ARP replies (same IP, different MAC)
unknown_ip_count = 0                    # Counter for unknown IP claims
INDICATORS_REQUIRED = 2                 # Number of indicators required to trigger warning
times_printed = 0                       # Tracks how many times we've printed unsolicited message (\100)


# --- Timestamp getter ---
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# --- Active Verification Function ---
# Sends an ARP request to the given IP and returns the MAC address from the reply
def verify_mac_by_challenge(ip_address):
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
    # Send the ARP request and wait for a response
    response, unanswered = sr(arp_request, timeout=0.5, verbose=0)
    # If we received a response, extract and return the MAC address
    if response:
        # Extract MAC address from the ARP reply
        return response[0][1][ARP].hwsrc

    # If no response, return None
    return None

# --- Packet Handler ---
# This function is called for every ARP packet captured and checks for indicators of falsities
def handle_arp(pkt):
    global unsolicited_count, conflict_count, unknown_ip_count, times_printed

    # Check if packet contains ARP layer, if not return early
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]        # Extract ARP layer from packet
    src_ip = arp.psrc     # Source IP address from ARP packet
    src_mac = arp.hwsrc   # Source MAC address from ARP packet
    op = arp.op           # Operation code for request/reply

    # --- Indicator 1: Conflicting MACs ---
    # Detect if this IP was previously associated with a different MAC
    if src_ip in arp_table and arp_table[src_ip] != src_mac:
        # Conflict detected
        old_mac = arp_table[src_ip]

        conflict_count += 1 # Increment conflict counter

        timestamp = get_timestamp()
        print(f"[{timestamp}] CONFLICT: {src_ip} changed from {old_mac} to {src_mac}")

    # --- Indicator 2: Unknown IP Claims ---
    if src_ip not in arp_table:
        if src_ip != gw_ip and src_mac != my_mac: # Only challenge NON-gateway devices
            real_mac = verify_mac_by_challenge(src_ip)

            if real_mac is None:
                # No response received meaning fake/unassigned IP
                timestamp = get_timestamp()
                print(f"[{timestamp}] UNKNOWN IP: {src_ip} claimed by {src_mac} did not respond to challenge")
                unknown_ip_count += 1
            else:
                # Device responded so we will update our table with the verified MAC
                arp_table[src_ip] = real_mac

        else:
            # Gateway discovered meaning trust first observation
            arp_table[src_ip] = src_mac

    # Save or update the IP -> MAC mapping in our table
    arp_table[src_ip] = src_mac

    # --- Indicator 3: Unsolicited ARP replies/requests ---
    # Check if this is an ARP reply (op=2) or request (op=1) where the target IP doesn't match the source IP (indicating unsolicited ARP)
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
    global unsolicited_count, conflict_count, unknown_ip_count

    indicators = 0  # Counter for how many types of suspicious activity detected

    # Check if we've seen any conflicting MAC addresses
    if conflict_count > 0:
        indicators += 1

    # Check if we've seen any unknown IP claims
    if unknown_ip_count > 0:
        indicators += 1

    # Check if we've seen any unsolicited ARP packets
    if unsolicited_count > 0:
        indicators += 1

    # If we have enough indicators print warning
    if indicators >= INDICATORS_REQUIRED:
        timestamp = get_timestamp()
        print(f"\n[{timestamp}] \n !!! WARNING !!!")
        print("ARP Spoofing detected!!!!!")
        print(f"Conflicts: {conflict_count}")
        print(f"Unsolicited Replies/Requests: {unsolicited_count}")
        print(f"Unknown IP Claims: {unknown_ip_count}\n")

        # Reset indicator counters after warning is issued
        unsolicited_count = 0
        conflict_count = 0
        unknown_ip_count = 0

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