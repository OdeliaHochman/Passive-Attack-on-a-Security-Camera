from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
import threading
import os, time
import random

bssids = {}  # Found BSSIDs


def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig


def addSSID(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt.getlayer(Dot11).addr2
        ssid = pkt.getlayer(Dot11Elt).info
        if bssid not in bssids:
            bssids[bssid] = ssid
            if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
                print("Hidden Network Detected")
            print("New network detected! Mac address: %s Name: %s" % (bssid, ssid))


def start(interface):
    print('Start sniffing networks in %s interface' % interface)
    thread = threading.Thread(target=hopper, args=(interface,), name="hopper")
    thread.daemon = True
    thread.start()

    sniff(iface=interface, prn=addSSID)


