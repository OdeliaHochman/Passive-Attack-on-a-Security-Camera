from scapy.all import *
from scapy.layers.dot11 import Dot11



network = ''
stations = []


def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig


def findStations(packet):
    transmitter_address = packet.getlayer(Dot11).addr2
    receiver_address = packet.getlayer(Dot11).addr1
    if transmitter_address == network:
        if receiver_address not in stations:
            stations.append(receiver_address)
            print('New device detected on the chosen network: %s' % receiver_address)


def start(interface, network_name):
    print('Start searching to devices in %s (%s) network' % (network_name, network))
    thread = threading.Thread(target=hopper, args=(interface,), name="hopper")
    thread.daemon = True
    thread.start()

    sniff(iface=interface, prn=findStations)


