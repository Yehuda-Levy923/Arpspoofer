import argparse
parser = argparse.ArgumentParser()

parser.add_argument('-h', '--help',                    help='Show this help message and exit')
parser.add_argument('-i', '--interface', type=str,     help='Decide what interface to use')
parser.add_argument('-s', '--src',       type=str,     help='The address you want for the attacker')
parser.add_argument('-d', '--delay',     type=float,   help='Delay (in seconds) between messages')
parser.add_argument('-gw',               type=bool,    help='Should GW be attacked as well')
parser.add_argument('-t', '--target',    type=str,     help='IP of target')

args = parser.parse_args()

