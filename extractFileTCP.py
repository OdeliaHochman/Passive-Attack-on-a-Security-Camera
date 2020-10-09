from scapy.all import *

# Read tcp streams from pcap file and save it as raw bytes file
def TcpPcapToRawBytesFile():
 #read tcpstream from pcap file
 pcap = PcapReader("my-packets.pcap")
 rawBytesFile="rawBytesFile"
 #create file for saving the raw bytes
 with open(rawBytesFile, "wb") as f:
  for pkt in pcap:
    if Raw in pkt:
        #convert TCP row to bytes
        data = bytes(pkt[Raw])
        f.write(data)

 return rawBytesFile



