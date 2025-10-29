import argparse
import time

interface = 'first interface available'
src = 'gateway IP address'
delay = 2

parser = argparse.ArgumentParser()

#parser.add_argument('-h', '--help',                    help='Show this help message and exit')
parser.add_argument('-i', '--interface', type=str,     help='Decide what interface to use')
parser.add_argument('-s', '--src',       type=str,     help='The address you want for the attacker')
parser.add_argument('-d', '--delay',     type=float,   help='Delay (in seconds) between messages')
parser.add_argument('-gw',               action='store_true',    help='Should GW be attacked as well')
parser.add_argument('-t', '--target',    type=str,     help='IP of target')

args = parser.parse_args()

if args.interface:
    interface = args.interface

if args.src:
    src = args.src

if args.delay:
    delay = args.delay

if args.target is None:
    print("error, must specify a target")
    exit()

target = args.target

'''
print("interface :", interface)
print("src :", src)
print("delay:", delay)
print("gw :", args.gw)
print("target :", target)
'''

if (not args.gw):
    while(True):
        print("sending '" + src + " is at ' to " + target + "using " + interface)
        time.sleep(delay)
else:
    while(True):
        print("sending '" + src + " is at ' to " + target + "using " + interface)
        print("sending '" + target + " is at ' to " + src + "using " + interface)
        time.sleep(delay)
