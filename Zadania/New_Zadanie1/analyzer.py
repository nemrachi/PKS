from datetime import date
import os
from socket import fromshare
import struct
from scapy.all import *
from protocols import getProtocols

# ...zoznam vsetkych IP adries vysielajucich uzlov a ich pocty
ip_list = []
ip_count = []
# ...premenne pri ARP komunikacii (pocet komunikacii a IP adresy)
arp_num = 0
arp_src_ip = []
arp_targ_ip = []
arp_frames = {0: {'source_ip': '', 'target_ip': ''}}
# ...premenne pri komunikacii protokolv nad TCP/UDP (pocet a pary portov)
communication_number = 0
port_pairs = {0: {'ports': (), 'ip_pairs': ()}}
# ...premenne pri ICMP komunikacii (pocet a pary IP adries)
icmp_num = 0
icmp_frames = {0: {'ip_pairs': ()}}
# ...premenne pri TFTP komunikacii
tftp_num = 0
tftp_src_port = []
tftp_frames = {0: {'ports': (), 'ip_pairs': ()}}


class Analyzer:

    def __init__(self, dump, outChoice):
        self.dump = dump
        self.outFile, self.stdout = None, None
        if (outChoice == "f"):
            self.stdout = sys.stdout
            self.outFile = open("analyzer_output.txt", "w")
            sys.stdout = self.outFile

        self.outputChoice = outChoice
        self.protocols = getProtocols()
        

    def firstPoint(self):
        frameCount = 0

        for frame in self.dump:
            baFrame = bytearray(bytes(frame))

            frameCount += 1

            lenPcapApi = len(baFrame)
            lenFrame = len(baFrame) + 4 if (len(baFrame) > 60) else 64
            
            destMac, sourceMac, frameType = self.getMacAddressessAndType(baFrame)
            frameTypeName, etherType, protocol = self.getFrameType(frameType, baFrame)
            # protocol, sourceIp, destIp = self.getProtocolAndIp(baFrame)

            print("ramec " + str(frameCount))
            print("dlzka ramca poskytnuta pcap API - " + str(lenPcapApi) + " B")
            print("dlzka ramca prenasaneho po mediu - " + str(lenFrame) + " B")
            print(etherType, frameTypeName, protocol)
            print("zdrojová MAC adresa: " + destMac)
            print("cielova MAC adresa: " + sourceMac)
            print("\n")


    def getMacAddressessAndType(self, frameData: bytearray) -> Tuple[str, str, str]:
        destMac, sourceMac, type = struct.unpack("!6s6sH", frameData[:14])
        destMac = map("{:02X}".format, sourceMac)
        sourceMac = map("{:02X}".format, sourceMac)
        destMac = " ".join(destMac)
        sourceMac = " ".join(sourceMac)
        return destMac, sourceMac,  type


    def getFrameType(self, type: str, data: bytearray) -> str:
        if type > 1500:
            etherType = self.getEtherType(type)
            return "Ether II", etherType, None
        else:
            ieeeType, protocol = self.getIeeeType(type, data)
            return "IEE 802.3", ieeeType, protocol

    def getEtherType(self, type: str) -> str:
        return self.protocols[self.hex2(type)]

    # IEEE 802.2 LLC, IEEE 802.2 SNAP, IEEE 802.3 Raw
    def getIeeeType(self, type: str, data: bytearray) -> Tuple[str, str]:
        ieeeType, protocol = None, None
        payload = struct.unpack("!BB", data[14:16])
        info = map("{:02X}".format, payload)
        info = "".join(info)

        print("payload: " + str(payload))
        print("info: " + str(info))

        return ieeeType, protocol



    def getProtocolAndIp(self, frameData: bytearray):
        protocol, sourceIp, destIp = struct.unpack("!", frameData[26:])

    def checkFilter(self, filter) -> bool:
        if filter == "":
            return False

        for ptKey in self.protocols:
            if ptKey == filter:
                return True

        return False


    

    def ieeeTypes(self, type, frameData):
        etherType, protocol = None, None
        payload = struct.unpack("!BB", frameData[:2])
        bytes = map("{:02x}".format, payload)
        bytes = "".join(bytes).upper()

        protocol = list(self.protocols.keys())[list(self.protocols.values()).index(payload[0])]
        try:
            type = list(self.protocols.keys())[list(self.protocols.values()).index(bytes)]
        except ValueError:
            type = "IEEE 802.2 - LLC"

        if type == "IEEE 802.2 - LLC SNAP":
            ether_type = get_snap_ethertype(data)

        return type, protocol, ether_type


    def hex2(self, n):
        x = "{:02x}".format(n)
        return ('0' * (len(x) % 2)) + x
