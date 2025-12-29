from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, sniff

interface = conf.iface

p = sniff(count = 1, lfilter = lambda pac: DNS in pac and pac[DNS].qr == 0, iface = interface)
p = p[0]
domain = p[DNSQR].qname
ip_DNS_server = p[IP].dst
d_type = p[DNSQR].qtype
s = (IP(dst=ip_DNS_server)
     / UDP(dport=53)
     / DNS(rd=1, qd=DNSQR(qname=domain, qtype = d_type)))

dns_answer = sr1(s, timeout=5, verbose=False)
if dns_answer:
    dns_answer =


