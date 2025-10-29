import argparse
import time
from scapy.all import conf

interface = conf.iface
src = conf.route.route('0.0.0.0')[2]
DELAY = 2

parser = argparse.ArgumentParser()

parser.add_argument('-i', '--interface', type=str,               help='Decide what interface to use')
parser.add_argument('-s', '--src',       type=str,               help='The address you want for the attacker')
parser.add_argument('-d', '--delay',     type=float,             help='Delay (in seconds) between messages')
parser.add_argument('-gw',               action='store_true',    help='Should GW be attacked as well')
parser.add_argument('-t', '--target',    type=str, required=True,help='IP of target')

args = parser.parse_args()

if args.interface:
    interface = args.interface

if args.src:
    src = args.src

if args.delay:
    delay = args.delay

target = args.target

if not args.gw:
    while True:
        print("sending '" + src + " is at ' to " + target + " using " + interface)
        time.sleep(DELAY)
else:
    while True:
        print("sending '" + src + " is at ' to " + target + " using " + interface)
        print("sending '" + target + " is at ' to " + src + " using " + interface)
        time.sleep(DELAY)
