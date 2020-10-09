from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11FCS, TCP, IP
from scapy.layers.l2 import ARP

from colors import bcolors
import os

interface = ''
device_mac = ''
count = 0


def saveToPcap(packet):
    global count
    wrpcap("my-packets.pcap", packet, append=True)
    print('New packet captured [+]')
    print('count: %s' % count)
    count += 1


def checkData(packet):

            saveToPcap(packet)


def start(channel):
    os.system('iwconfig %s channel %d' % (interface, channel))
    print(bcolors.OKGREEN + 'Start capturing wireless data of the selected device: %s.' % device_mac + bcolors.ENDC)
    print(bcolors.OKGREEN + 'For stopping capturing put Ctrl+C.' + bcolors.ENDC)
    time.sleep(3)
    # sniffer TCP packets by ip source of camera 
    sniff(filter="ip src 10.100.102.33 and tcp",iface=interface, prn=checkData)