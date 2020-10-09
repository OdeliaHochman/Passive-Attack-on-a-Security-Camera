from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
import os, time
from colors import bcolors

channel = ''
network_mac = ''


def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig


def findChannel(pkt):
    global channel
    global network_mac
    if channel == '':
        time.sleep(0.1)
        print('searching...')
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.getlayer(Dot11).addr2
            if bssid == network_mac:
                ch = int(ord(pkt[Dot11Elt:3].info))
                channel = ch
                print(bcolors.OKGREEN + "The network channel has been detected! (%s)" % channel + bcolors.ENDC)
                print(bcolors.HEADER + "Press Ctrl+C to continue." + bcolors.ENDC)


def start(interface):
    print(bcolors.OKGREEN + 'Start searching to the channel of the chosen network...' + bcolors.ENDC)
    time.sleep(2)
    thread = threading.Thread(target=hopper, args=(interface,), name="hopper")
    thread.daemon = True
    thread.start()

    sniff(iface=interface, prn=findChannel)
