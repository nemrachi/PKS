from datetime import date
import os
from socket import fromshare
import struct
from types import FrameType
from scapy.all import *


class Analyser:

    def __init__(self, dump: PacketList, traceName: str, outChoice: str):
        self.dump = dump # data from pcap file
        self.outputFile = None # file for saving output
        self.outputChoice = outChoice

        if (self.outputChoice == "f"):
            self.path = os.path.dirname(__file__) + "\outputFiles\\" + traceName + ".txt" 
            self.outputFile = open(self.path, "w")

        self.frames, self.protocols, self.ipProtocols, self.ports = getFramesProtocolsPorts()

    class Frame:

        def __init__(self, baFrame: bytearray, frameCount: int):
            self.data = baFrame
            self.number = frameCount
            self.lenPcapApi = None
            self.lenFrame = None
            self.frameType = None
            self.destMac = None
            self.sourceMac = None
            self.protocol = {"main": None}
        

    def analyse(self):
        frameCount = 0

        destIpCount = {} # dict of receiving Ips with their counts

        for frame in self.dump:
            # frame counter
            frameCount += 1

            f = self.Frame(bytearray(bytes(frame)), frameCount)

            # lenghts of frame in pcap api and in real communication
            f.lenPcapApi = len(f.data)
            f.lenFrame = len(f.data) + 4 if (len(f.data) > 60) else 64
            
            # destination and source mac address, frame type, inner protocol of frame
            f.destMac, f.sourceMac, frameType = self.getMacAddressessAndFrameType(f.data)
            f.frameType, f.protocol["main"] = self.getFrameType(frameType, f.data)

            if (f.protocol["main"] == self.protocols["0800"]): # if IPv4
                destIpCount, frame = self.getProtocolAndIpFromIpv4(destIpCount, f)

            # print in console or to the file
            if (self.outputChoice == "f"):
                self.printInfoToFile(f)
            else:
                self.printInfo(f)

        if (self.outputChoice == "f"):
            if (destIpCount != {}): # only for tcp
                self.printAllDestIpv4ToFile(destIpCount) # point 3
            self.outputFile.close()
        else:
            if (destIpCount != {}):
                self.printAllDestIpv4(destIpCount) # point 3


    def getMacAddressessAndFrameType(self, frameData: bytearray) -> Tuple[str, str, str]:
        # type have decimal value
        destMac, sourceMac, type = struct.unpack("!6s6sH", frameData[:14])
        destMac = " ".join(map("{:02X}".format, destMac))
        sourceMac = " ".join(map("{:02X}".format, sourceMac))
        return destMac, sourceMac, type


    def getFrameType(self, type: str, data: bytearray) -> Tuple[str, str]:
        if type > 1500:
            return self.getEtherProtocol(type)
        else:
            return self.getIeeeType(data)


    # Ether II protocol
    def getEtherProtocol(self, type: str) -> Tuple[str, str]:
        hexType = self.hex2(type)
        try:
            prot = self.protocols[hexType]
        except KeyError: 
            prot = None
            print(">>> Protocol " + hexType + " not found.")

        return "Ether II", prot


    # 802.3 LLC+SNAP, 802.3 LLC, 802.3 Raw and protocol
    def getIeeeType(self, data: bytearray) -> Tuple[str, str]:
        llHeader = struct.unpack("!BB", data[14:16])
        llHeader = "".join(map("{:02x}".format, llHeader))

        try:
            ieeeType = self.frames[llHeader]
        except KeyError: 
            ieeeType = None

        protocol = None

        if ("SNAP" in ieeeType): # SNAP
            protocol = self.getIeeeSnapProtocol(data)
        elif ("RAW" in ieeeType): # RAW
            protocol = "IPX"
        else: # LLC
            ieeeType = self.frames["e0e0"]
            protocol = self.protocols[llHeader[:2]]

        return ieeeType, protocol


    def getIeeeSnapProtocol(self, data: bytearray) -> str:
        hexProt = struct.unpack("!BB", data[20:22])
        hexProt = "".join(map("{:02x}".format, hexProt))

        try:
            protocol = self.protocols[hexProt]
        except KeyError: 
            protocol = None
            print(">>> SNAP ethertype " + hexProt + " not found.")

        return protocol


    def getProtocolAndIpFromIpv4(self, destIpCount: dict, frame: Frame) -> Tuple[dict, Frame]:
        ipProtocol, sourceIp, destIp = struct.unpack("!B2x4s4s", frame.data[23:34])
        frame.protocol["sourceIp"] = ".".join(map(str, sourceIp))
        destIp = ".".join(map(str, destIp))
        frame.protocol["destIp"] = destIp
        ipProtocol = self.hex2(ipProtocol)

        try:
            frame.protocol["ipProtocol"] = self.ipProtocols[ipProtocol]
        except KeyError: 
            print(">>> Port from IPv4 " + str(ipProtocol) + " not found.")
            frame.protocol["ipProtocol"] = None

        if (frame.protocol["ipProtocol"] == "TCP"):
            if destIp not in destIpCount:
                destIpCount[destIp] = 1
            else:
                destIpCount[destIp] = destIpCount[destIp] + 1

        return destIpCount, frame


    # convert decimal number to 2,4,6,... places hex number
    def hex2(self, dec: str) -> str:
        x = "{:02x}".format(dec)
        return ('0' * (len(x) % 2)) + x


    def printInfo(self, frame: Frame):
        print("ramec " + str(frame.number))
        print("dlzka ramca poskytnuta pcap API - " + str(frame.lenPcapApi) + " B")
        print("dlzka ramca prenasaneho po mediu - " + str(frame.lenFrame) + " B")
        print(frame.frameType)
        print("zdrojova MAC adresa: " + frame.sourceMac)
        print("cielova MAC adresa: " + frame.destMac)

        if (frame.protocol["main"] != None):
            print(frame.protocol["main"] )

            if (frame.protocol["main"] == self.protocols["0800"]): # if IPv4
                print(frame.protocol["sourceIp"])
                print(frame.protocol["destIp"])

                if (frame.protocol["ipProtocol"] != None):
                    print(frame.protocol["ipProtocol"])
                    
        print(hexdump(frame.data, True))
        print("\n")


    def printInfoToFile(self, frame: Frame):
        self.outputFile.write("ramec " + str(frame.number) + "\n")
        self.outputFile.write("dlzka ramca poskytnuta pcap API - " + str(frame.lenPcapApi) + " B" + "\n")
        self.outputFile.write("dlzka ramca prenasaneho po mediu - " + str(frame.lenPcapApi) + " B" + "\n")
        self.outputFile.write(frame.frameType + "\n")
        self.outputFile.write("zdrojova MAC adresa: " + frame.sourceMac + "\n")
        self.outputFile.write("cielova MAC adresa: " + frame.destMac + "\n")

        if (frame.protocol["main"]  != None):
            self.outputFile.write(frame.protocol["main"]  + "\n")

            if (frame.protocol["main"] == self.protocols["0800"]): # if IPv4
                if (frame.protocol["ipProtocol"] != None):
                    self.outputFile.write(frame.protocol["ipProtocol"] + "\n")

                self.outputFile.write("zdrojova IP adresa: " + frame.protocol["sourceIp"] + "\n")
                self.outputFile.write("cielova IP adresa: " + frame.protocol["destIp"] + "\n")

        self.outputFile.write(hexdump(frame.data, True) + "\n\n")

    
    def printAllDestIpv4(self, destIps: dict):
        print("Zoznam IP adries vsetkych prijimajucich uzlov:")
        for destIp in destIps:
            print(destIp)

        maxPackIp = max(destIps, key = lambda key: destIps[key])
        print("\nIP adresa, ktora sumarne prijala najvacsi pocet paketov: " + maxPackIp)
        print("Pocet paketov, ktore prijala: " + str(destIps[maxPackIp]))

    
    def printAllDestIpv4ToFile(self, destIps: dict):
        self.outputFile.write("Zoznam IP adries vsetkych prijimajucich uzlov:" + "\n")
        for destIp in destIps:
            self.outputFile.write(destIp + "\n")

        maxPackIp = max(destIps, key = lambda key: destIps[key])
        self.outputFile.write("\nIP adresa, ktora sumarne prijala najvacsi pocet paketov: " + maxPackIp + "\n")
        self.outputFile.write("Pocet paketov, ktore prijala: " + str(destIps[maxPackIp]) + "\n")



# get frame types and protocols from txt file and save them in dictionary
def getFramesProtocolsPorts() -> Tuple[dict, dict, dict, dict]:
    frames, protocols, ipProtocols, ports = {}, {}, {}, {}
    state = 0

    filePath = os.path.dirname(__file__) + "\\framesProtocolsPorts.txt"

    if os.path.isfile(filePath):
        file = open(filePath, 'r')
        lines = file.readlines()
        file.close()

        for l in lines:
            if l.startswith("#"):
                if l.startswith("# frames"):
                    state = 1
                elif l.startswith("# protocols"):
                    state = 2
                elif l.startswith("# ip "):
                    state = 3
                elif l.startswith("# ports"):
                    state = 4
                else:
                    continue
            
            else:
                # dict key is hex number of frame/protocol/port
                if l != "\n":
                    if (state == 1):
                        sl = l.split(" ", 1)
                        frames[sl[0]] = sl[1].rstrip()
                    elif (state == 2):
                        sl = l.split(" ", 1)
                        protocols[sl[0]] = sl[1].rstrip()
                    elif (state == 3):
                        sl = l.split(" ", 1)
                        ipProtocols[sl[0]] = sl[1].rstrip()
                    elif (state == 4):
                        sl = l.split(" ", 1)
                        ports[sl[0]] = sl[1].rstrip()
                    else:
                        raise ValueError("state variable has wrong value")

    else:
        print(">>> Can't open the file or the file doesn't exists.\n")
        exit(True)

    return frames, protocols, ipProtocols, ports
