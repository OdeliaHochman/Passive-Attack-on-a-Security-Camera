from pip._vendor.distlib.compat import raw_input
import findNetworks
import findChannel
import findStations
import packetSaver
import extractFileTCP
import convertTcpStreamToImages
import sys
import os
import time
from os import system
from colors import bcolors

file_name = "my-packets.pcap"


# ----------------------------------------------------------------------------------------------------------------------
print
print(bcolors.OKGREEN + 'Welcome to the packet sniffer program!' + bcolors.ENDC)
time.sleep(2)
# explanation how to stop processes
print(
    bcolors.OKGREEN + 'At each stage of the program execution, you can stop the current process by pressing Ctrl+C.' + bcolors.ENDC)
time.sleep(2)
# the user must to start the program with interface in the managed mode and program will turn it to the monitor mode
print(
    bcolors.OKGREEN + 'Before starting sniffing is necessary to turn your interface to the monitor mode.' + bcolors.ENDC)
time.sleep(2)
# list of available interfaces
interfaces = os.listdir('/sys/class/net/')
print(bcolors.OKGREEN + 'Your available interfaces: %s' % interfaces + bcolors.ENDC)
time.sleep(2)

# -------------------------------------------------Interface choosing---------------------------------------------------
# user have to choose one of the available interfaces
interface = ''
while interface == '':
    interface = raw_input(
        bcolors.HEADER + 'Please select one of the available interfaces for the wifi capturing: ' + bcolors.ENDC)
    # if user selected right interface then break otherwise chose again
    if interface in interfaces:
        break
    else:
        print(bcolors.WARNING + 'The selected interface does not exists... Please select again.' + bcolors.ENDC)
        interface = ''

# switch interface to monitor mode by airmong command
print(bcolors.OKBLUE)
system('airmon-ng start %s' % interface)
print(bcolors.ENDC)
interface = interface + 'mon'

# ----------------------------------------------------Remove old pcap---------------------------------------------------
if os.path.exists(file_name):
    os.remove(file_name)

# -------------------------------------------------Networks searching---------------------------------------------------
print(bcolors.OKGREEN + 'The interface is selected and the program is ready to continue!' + bcolors.ENDC)
next_step = raw_input(bcolors.HEADER + 'To stop press Ctrl+C, to continue press y: ' + bcolors.ENDC)
print
if next_step != 'y':
    print(bcolors.WARNING + 'The program was stopped by the user...' + bcolors.ENDC)
    system('airmon-ng stop %s' % interface)
    sys.exit(-1)

# find all ap in the area using the selected interface
findNetworks.start(interface)
print
# choose network from found networks
networks = findNetworks.bssids
# if no networks was found then exit from the program otherwise continue
if len(networks) == 0:
    print(bcolors.FAIL + 'Not found any networks...' + bcolors.ENDC)
    sys.exit(-1)

# next step is to choose one of the found networks
network_name = ''
network_mac = ''
while network_name == '':
    network_mac = raw_input(bcolors.HEADER + 'Select the network (BSSID) to continue: ' + bcolors.ENDC)
    # if network exist the choose it otherwise choose again
    if networks.__contains__(network_mac):
        network_name = networks[network_mac]
    else:
        print(bcolors.WARNING + 'The selected network does not exist. Please select again!' + bcolors.ENDC)

# -------------------------------------------------Channel searching----------------------------------------------------
print(bcolors.OKGREEN + 'The network is selected and the program is ready to continue!' + bcolors.ENDC)
next_step = raw_input(bcolors.HEADER + 'To stop press Ctrl+C, to continue press y: ' + bcolors.ENDC)
print
if next_step != 'y':
    print(bcolors.WARNING + 'The program was stopped by the user...' + bcolors.ENDC)
    system('airmon-ng stop %s' % interface)
    sys.exit(-1)

# install network mac before searching to the channel
findChannel.network_mac = network_mac

# start searching to the channel
findChannel.start(interface)
print

channel = findChannel.channel
if channel == '':
    print(bcolors.FAIL + 'The network channel not found...' + bcolors.ENDC)
    sys.exit(-1)

# -------------------------------------------------Devices searching----------------------------------------------------
print(bcolors.OKGREEN + 'The channel was selected and the program is ready to continue!' + bcolors.ENDC)
next_step = raw_input(bcolors.HEADER + 'To stop press Ctrl+C, to continue press y: ' + bcolors.ENDC)
print
if next_step != 'y':
    print(bcolors.WARNING + 'The program was stopped by the user...' + bcolors.ENDC)
    system('airmon-ng stop %s' % interface)
    sys.exit(-1)

# install the selected network before start searching stations
findStations.network = network_mac

# start searching to the all stations of this network
findStations.start(interface, network_name)
print

# select station from founded stations
stations = findStations.stations

# if no stations was found then stop the program otherwise continue
if len(stations) == 0:
    print(bcolors.FAIL + 'Not found any devices connected to the chosen network (%s)...' % network_name + bcolors.ENDC)
    sys.exit(-1)

# the next step is to choose one if the found stations
station_mac = ''
while station_mac == '':
    filter_station = raw_input(bcolors.HEADER + 'Select the device to continue: ' + bcolors.ENDC)
    # if station exist then continue otherwise choose again
    if filter_station in stations:
        station_mac = filter_station
    else:
        print(bcolors.WARNING + 'The selected device does not exist. Please select again!' + bcolors.ENDC)

# -------------------------------------------------Packet capturing-----------------------------------------------------
print(bcolors.OKGREEN + 'The device was selected and the program is ready to continue!' + bcolors.ENDC)
next_step = raw_input(bcolors.HEADER + 'To stop press Ctrl+C, to continue press y: ' + bcolors.ENDC)
print
if next_step != 'y':
    print(bcolors.WARNING + 'The program was stopped by the user...' + bcolors.ENDC)
    system('airmon-ng stop %s' % interface)
    sys.exit(-1)

# ----------------------------------------------------------------------------------------------------

# install the actual network before start capturing
packetSaver.network_ip = station_mac

# install the actual interface before start capturing
packetSaver.interface = interface

# capture packets of the selected device
packetSaver.start(channel)

print
print(bcolors.OKGREEN + 'Congratulations! Captured data file created!' + bcolors.ENDC)
# system('airmon-ng stop %s' % interface)
print(bcolors.OKGREEN + 'The interface has been returned to manage mode!' + bcolors.ENDC)


print(bcolors.OKGREEN + 'Do you want to get the images?' + bcolors.ENDC)
next_step = raw_input(bcolors.HEADER + 'To continue press y: ' + bcolors.ENDC)
print

convertTcpStreamToImages.createImagesFolder()
fname = extractFileTCP.TcpPcapToRawBytesFile()
with open(fname, 'rb') as f:
    convertTcpStreamToImages.data=f.read()
    convertTcpStreamToImages.pl=([p for p in convertTcpStreamToImages.data])
    file_stats = os.stat(fname)
    convertTcpStreamToImages.fileLen = file_stats.st_size
    print("fileLen = %d", convertTcpStreamToImages.fileLen)
    convertTcpStreamToImages.findStartOfImage(0, convertTcpStreamToImages.numOfImage)

# Open Image
# hasImage = False
# counterTrys=0
# while not hasImage:
#     filter_image = raw_input(bcolors.HEADER + 'Choose Image number to open: ' + bcolors.ENDC)
#     im = "image{0}.jpg".format(filter_image)
#     image = "{0}image{1}.jpg".format(convertTcpStreamToImages.dirName,filter_image)
#     if convertTcpStreamToImages.dirName.__contains__(im):
#         hasImage = True
#         convertTcpStreamToImages.openImage(image)
#     else:
#         print(bcolors.WARNING + 'The Image number you selected does not exist. Try again!' + bcolors.ENDC)
#         counterTrys+=1
#         if counterTrys == 3:
#             sys.exit(0)
