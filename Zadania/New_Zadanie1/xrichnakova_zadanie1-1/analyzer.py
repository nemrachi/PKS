from datetime import date
import os
from socket import fromshare
import struct
from types import FrameType
from scapy.all import *
from protocols import getProtocols


class Analyzer:

    def __init__(self, dump, traceName, outChoice):
        self.dump = dump
        self.outputFile = None
        self.outputChoice = outChoice

        if (self.outputChoice == "f"):
            self.path = os.path.dirname(__file__) + "\outputFiles\\" + traceName + ".txt" 
            self.outputFile = open(self.path, "w")

        self.protocols = getProtocols()
        

    def firstPoint(self):
        frameCount = 0

        for frame in self.dump:
            baFrame = bytearray(bytes(frame))

            frameCount += 1

            lenPcapApi = len(baFrame) # frames lenght from pcap api
            lenFrame = len(baFrame) + 4 if (len(baFrame) > 60) else 64 # real frames lenght
            
            destMac, sourceMac, frameType = self.getMacAddressessAndFrameType(baFrame)
            frameTypeName, protocol = self.getFrameType(frameType, baFrame)

            if (self.outputChoice == "f"):
                self.printInfoToFile(frameCount, lenPcapApi, lenFrame, frameTypeName, sourceMac, destMac, protocol, baFrame)
            else:
                self.printInfo(frameCount, lenPcapApi, lenFrame, frameTypeName, sourceMac, destMac, protocol, baFrame)

        if (self.outputChoice == "f"):
            self.outputFile.close()


    def getMacAddressessAndFrameType(self, frameData: bytearray) -> Tuple[str, str, str]:
        destMac, sourceMac, type = struct.unpack("!6s6sH", frameData[:14])
        destMac = map("{:02X}".format, destMac)
        sourceMac = map("{:02X}".format, sourceMac)
        destMac = " ".join(destMac)
        sourceMac = " ".join(sourceMac)
        return destMac, sourceMac,  type


    def getFrameType(self, type: str, data: bytearray):
        if type > 1500:
            return "Ether II", self.getEtherProtocol(type)
        else:
            return self.getIeeeType(data)


    # Ether II protocol
    def getEtherProtocol(self, type: str) -> str:
        return self.protocols[self.hex2(type)]


    # 802.3 LLC+SNAP, 802.3 LLC, 802.3 Raw
    def getIeeeType(self, data: bytearray) -> Tuple[str, str]:
        ieeeType = None
        llHeader = struct.unpack("!BB", data[14:16])
        llHeader = map("{:02x}".format, llHeader)
        llHeader = "".join(llHeader)

        protocol = self.protocols[llHeader[:2]]

        if (protocol == "SNAP"): # SNAP
            ieeeType = self.protocols[llHeader]
            protocol = None
            # inner protocol
        elif (protocol == "Global DSAP"): # RAW
            ieeeType = self.protocols[llHeader]
            protocol = None
            # inner protocol
        else: # LLC
            ieeeType = self.protocols["e0e0"]

        return ieeeType, protocol


    def hex2(self, n):
        x = "{:02x}".format(n)
        return ('0' * (len(x) % 2)) + x


    def printInfo(self, count, lenApi, lenFrame, frameType, sourceMac, destMac, protocol, frame):
        print("ramec " + str(count))
        print("dlzka ramca poskytnuta pcap API - " + str(lenApi) + " B")
        print("dlzka ramca prenasaneho po mediu - " + str(lenFrame) + " B")
        print(frameType)
        print("zdrojova MAC adresa: " + sourceMac)
        print("cielova MAC adresa: " + destMac)
        if (protocol != None):
            print(protocol)
        print(hexdump(frame, True))
        print("\n")


    def printInfoToFile(self, count, lenApi, lenFrame, frameType, sourceMac, destMac, protocol, frame):
        self.outputFile.write("ramec " + str(count) + "\n")
        self.outputFile.write("dlzka ramca poskytnuta pcap API - " + str(lenApi) + " B" + "\n")
        self.outputFile.write("dlzka ramca prenasaneho po mediu - " + str(lenFrame) + " B" + "\n")
        self.outputFile.write(frameType + "\n")
        self.outputFile.write("zdrojova MAC adresa: " + sourceMac + "\n")
        self.outputFile.write("cielova MAC adresa: " + destMac + "\n")

        if (protocol != None):
            self.outputFile.write(protocol + "\n")

        self.outputFile.write(hexdump(frame, True) + "\n\n")
