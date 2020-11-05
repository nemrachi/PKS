from datetime import date
import os
from socket import fromshare
import struct
from types import FrameType
from scapy.all import *


class Analyser:

    def __init__(self, dump: PacketList, traceName: str, filteredProtocol: str, outChoice: str):
        self.dump = dump # data from pcap file
        self.outputFile = None # file for saving output
        self.filteredProtocol = filteredProtocol
        self.outputChoice = outChoice

        if (self.outputChoice == "f"):
            self.path = os.path.dirname(__file__) + "\outputFiles\\" + traceName + ".txt" 
            self.outputFile = open(self.path, "w")

        self.frames, self.protocols, self.ipProtocols, self.ports = getFramesProtocolsPorts()

        # self.checkFilter()

        # for point 4
        # analyse TCP/UDP communication
        self.tcpUdpCount = 0
        self.tcpUdpFrames = {0: {"ipPairs": (), "ports": ()}}
        # analyse TFTP
        self.tftpCount = 0
        self.tftFrames = {0: {"ipPairs": (), "ports": ()}}
        self.tftSourcePorts = []
        # analyse ICMP communication
        self.icmpCount = 0
        self.icmpFrames = {0: {"ipPairs": ()}}

    class Frame:

        def __init__(self, baFrame: bytearray, frameCount: int):
            self.data = baFrame
            self.number = frameCount
            self.lenPcapApi = None
            self.lenFrame = None
            self.frameType = None
            self.destMac = None
            self.sourceMac = None
            self.protocol = {"main": None} # dict for protocols, ip protocols and ports
            """
            how dict can looks like for different protocols:
            main: any-protocol
            main: IPv4, ipProtocol: TCP, sourceIp: , destIp: , sourcePort: , destPort: , flagACK: , flagRST: , flagSYN: , flagFIN:
            main: IPv4, ipProtocol: UDP, sourceIp: , destIp: , sourcePort: , destPort:
            main: IPv4, ipProtocol: ICMP, sourceIp: , destIp: , msgType: 
            main: ARP, sourceIp: , sourceMac:, destIp: , destMac: , opcode:
            """
        

    def analyse(self):
        lldpCount = 0

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
                destIpCount, frame = self.getProtocolIpFromIpv4(destIpCount, f)
                frame = self.getPortsFromIpv4(frame)
            elif (f.protocol["main"] == self.protocols["0806"]): # if ARP
                frame = self.getIpFromArp(f)  
            elif (f.protocol["main"] == self.protocols["88cc"]) : # if LLDP
                lldpCount += 1 
                if (self.filteredProtocol == "LLDP"):
                    if (self.outputChoice == "f"):
                        self.printInfoToFile(f)
                        self.outputFile.write("pocet LLDP ramcov:" + str(lldpCount) + "\n") # doimplemnetacia
                    else:
                        self.printInfo(f)  
                        print("pocet LLDP ramcov:" + str(lldpCount)) # doimplemnetacia
                    
            if (self.filteredProtocol.rstrip() == "LLDP"):
                continue

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
        prot = None
        try:
            prot = self.protocols[hexType]
        except KeyError: 
            print(">>> Protocol " + hexType + " not found.")

        return "Ether II", prot


    # 802.3 LLC+SNAP, 802.3 LLC, 802.3 Raw and protocol
    def getIeeeType(self, data: bytearray) -> Tuple[str, str]:
        ieeeType = None
        llHeader = struct.unpack("!BB", data[14:16])
        llHeader = map("{:02x}".format, llHeader)
        llHeader = "".join(llHeader)

        protocol = self.protocols[llHeader[:2]]

        if (protocol == "SNAP"): # SNAP
            ieeeType = self.frames[llHeader]
            protocol = self.protocols[llHeader[:2]]
            # inner protocol
        elif (protocol == "Global DSAP"): # RAW
            ieeeType = self.frames[llHeader]
            protocol = "IPX"
            # inner protocol
        else: # LLC
            ieeeType = self.frames["e0e0"]

        return ieeeType, protocol


    def getIpFromArp(self, frame: Frame) -> Frame:
        opcode, sourceMac, sourceIp, destMac, destIp = struct.unpack("!H6s4s6s4s", frame.data[20:42])
        # ip adresses
        frame.protocol["sourceIp"] = ".".join(map(str, sourceIp))
        frame.protocol["destIp"] = ".".join(map(str, destIp))
        # mac adresses
        frame.protocol["sourceMac"] = " ".join(map("{:02X}".format, sourceMac))
        frame.protocol["destMac"] = " ".join(map("{:02X}".format, destMac))

        frame.protocol["opcode"] = opcode

        if (self.filteredProtocol == "ARP"):
            self.arpCommunication(frame)
        
        return frame


    def arpCommunication(self, frame: Frame):
        # vypisanie dvojic
        pass


    def getProtocolIpFromIpv4(self, destIpCount: dict, frame: Frame) -> Tuple[dict, Frame]:
        ipProtocol, sourceIp, destIp = struct.unpack("!B2x4s4s", frame.data[23:34])
        # ip adresses
        frame.protocol["sourceIp"] = ".".join(map(str, sourceIp))
        frame.protocol["destIp"] = ".".join(map(str, destIp))
        destIp = frame.protocol["destIp"]

        # protocol
        ipProtocol = self.hex2(ipProtocol)
        try:
            frame.protocol["ipProtocol"] = self.ipProtocols[ipProtocol]
        except KeyError: 
            print(">>> (frame: " + str(frame.number) + ") Protocol from IPv4 " + str(ipProtocol) + " not found.")
            frame.protocol["ipProtocol"] = None

        # destination ip count
        if destIp not in destIpCount:
            destIpCount[destIp] = 1
        else:
            destIpCount[destIp] += 1

        return destIpCount, frame


    def getPortsFromIpv4(self, frame: Frame) -> Frame:
        if (frame.protocol["ipProtocol"] == self.ipProtocols["01"]): # ICMP
            frame = self.getIcmpInfo(frame) # no ports for ICMP
            return frame
        elif (frame.protocol["ipProtocol"] == self.ipProtocols["06"]): # TCP
            frame = self.getTcpInfo(frame)
        elif (frame.protocol["ipProtocol"] == self.ipProtocols["11"]): # UDP
            frame = self.getUdpInfo(frame)

        # checks ports if exists
        try:
            sPortNum = frame.protocol["sourcePort"]
        except:
            return frame
        try:
            frame.protocol["sourcePort"] = self.ports[self.hex2(sPortNum)]
            frame.protocol["sourcePort"] = str(sPortNum) + " " + frame.protocol["sourcePort"]
        except KeyError: 
            # print(">>> (frame: " + str(frame.number) + ") Source port " + sPortNum + " from IPv4 not found.")
            frame.protocol["sourcePort"] = str(sPortNum)

        dPortNum = frame.protocol["destPort"]
        try:
            frame.protocol["destPort"] = self.ports[self.hex2(dPortNum)]
            frame.protocol["destPort"] = str(dPortNum) + " " + frame.protocol["destPort"]
        except KeyError: 
            # print(">>> (frame: " + str(frame.number) + ") Destination port " + dPortNum + " from IPv4 not found.")
            frame.protocol["destPort"] = str(dPortNum)

        # printing
        if (self.filteredProtocol != None):
            if (((self.filteredProtocol in frame.protocol["sourcePort"]) or (self.filteredProtocol in frame.protocol["destPort"])) and self.filteredProtocol != self.ports["45"]): # not TFTP
                self.tcpUdpCommunication(frame)
            elif ((self.filteredProtocol in frame.protocol["destPort"]) and (frame.protocol["destPort"] == self.ports["45"])): # if TFTP
                self.tftpCommunication(frame)

        return frame

    
    def getTcpInfo(self, frame: Frame) -> Frame:
        sPort, dPort, flags = struct.unpack("!HH8xH", frame.data[34:48])
        
        frame.protocol["sourcePort"] = sPort
        frame.protocol["destPort"] = dPort

        frame.protocol["flagACK"] = (flags & 16) >> 4
        frame.protocol["flagRST"] = (flags & 4) >> 2
        frame.protocol["flagSYN"] = (flags & 2) >> 1
        frame.protocol["flagFIN"] = (flags & 1)

        return frame


    def getUdpInfo(self, frame: Frame) -> Frame:
        sPort, dPort = struct.unpack("!HH", frame.data[34:38])

        frame.protocol["sourcePort"] = sPort
        frame.protocol["destPort"] = dPort

        return frame

    
    def tcpUdpCommunication(self, frame: Frame):
        counted = False
        # refactor
        for pair in range(self.tcpUdpCount + 1):
            if self.tcpUdpAreCounted(frame, pair):
                counted = True

        if counted:
            for pair in range(self.tcpUdpCount + 1):
                if self.tcpUdpAreCounted(frame, pair):
                    if (self.outputChoice == "f"):
                        self.printTcpUdpCommunicationToFile(frame, pair, False)
                    else:
                        self.printTcpUdpCommunication(frame, pair, False)
        else:
            self.tcpUdpCount += 1
            self.tcpUdpFrames[self.tcpUdpCount] = {}
            self.tcpUdpFrames[self.tcpUdpCount]["ipPairs"] = (frame.protocol["sourceIp"], frame.protocol["destIp"])
            self.tcpUdpFrames[self.tcpUdpCount]["ports"] = (frame.protocol["sourcePort"], frame.protocol["destPort"])

            if (self.outputChoice == "f"):
                self.printTcpUdpCommunicationToFile(frame, self.tcpUdpCount, True)
            else:
                self.printTcpUdpCommunication(frame, self.tcpUdpCount, True)


    def tcpUdpAreCounted(self, frame: Frame, pair: int) -> bool:
        # if pair of ip addresses are in self.icmpFrames, return True
        if ((frame.protocol["sourceIp"] in self.tcpUdpFrames[pair]["ipPairs"] and frame.protocol["destIp"] in self.tcpUdpFrames[pair]["ipPairs"])
            and (frame.protocol["sourcePort"] in self.tcpUdpFrames[pair]["ports"] and frame.protocol["destPort"] in self.tcpUdpFrames[pair]["ports"])):
            return True
        else:
            return False


    def tftpCommunication(self, frame: Frame):
        counted = False

        if ("45" in frame.protocol["destPort"]): # first UDP frame port 0d69
            print("prva komunikacia c.: " + str(self.tftpCount + 1))
            self.tftSourcePorts.append(frame.protocol["sourcePort"])
        
        else:
            # refactor
            for pair in range(self.tftpCount + 1):
                if self.tftpPairAreCounted(frame, pair):
                    counted = True

            if counted:
                for pair in range(self.tftpCount + 1):
                    if self.tftpPairAreCounted(frame, pair):
                        if (self.outputChoice == "f"):
                            self.outputFile.write("komunikacia c.: " + str(pair) + "\n")
                        else:
                            print("komunikacia c.: " + str(pair))
            else:
                self.tftpCount += 1
                self.tftFrames[self.tftpCount] = {}
                self.tftFrames[self.tftpCount]["ipPairs"] = (frame.protocol["sourceIp"], frame.protocol["destIp"])
                self.tftFrames[self.tftpCount]["ports"] = (frame.protocol["sourcePort"], frame.protocol["destPort"])
            
                if (self.outputChoice == "f"):
                    self.outputFile.write("komunikacia c.: " + str(self.tftpCount) + "\n")
                else:
                    print("komunikacia c.: " + str(self.tftpCount))


    def tftpPairAreCounted(self, frame: Frame, pair: int) -> bool:
        # if pair of ip addresses are in self.tftFrames, return True
        if ((frame.protocol["sourceIp"] in self.tftFrames[pair]["ipPairs"] and frame.protocol["destIp"] in self.tftFrames[pair]["ipPairs"])
            and (frame.protocol["sourcePort"] in self.tftFrames[pair]["ports"] and frame.protocol["destPort"] in self.tftFrames[pair]["ports"])):
            return True
        else:
            return False


    def getIcmpInfo(self, frame: Frame) -> Frame:
        msgType = struct.unpack("!B", frame.data[34:35])
        msgType = self.hex2(msgType[0])

        try:
            msgType = self.ports[msgType]
        except KeyError: 
            print(">>> (frame: " + str(frame.number) + ") ICMP type " + str(msgType) + " not found.")
            msgType = None

        frame.protocol["msgType"] = msgType

        if ((self.filteredProtocol != None) and (self.filteredProtocol == "ICMP")):
            self.icmpCommunication(frame)

        return frame


    def icmpCommunication(self, frame: Frame):
        counted = False
        # refactor
        for pair in range(self.icmpCount + 1):
            if self.icmpPairAreCounted(frame, pair):
                counted = True

        if counted:
            for pair in range(self.icmpCount + 1):
                if self.icmpPairAreCounted(frame, pair):
                    if (self.outputChoice == "f"):
                        self.printIcmpCommunicationToFile(frame, pair, False)
                    else:
                        self.printIcmpCommunication(frame, pair, False)
        else:
            self.icmpCount += 1
            self.icmpFrames[self.icmpCount] = {}
            self.icmpFrames[self.icmpCount]["ipPairs"] = (frame.protocol["sourceIp"], frame.protocol["destIp"])
           
            if (self.outputChoice == "f"):
                self.printIcmpCommunicationToFile(frame, self.icmpCount, True)
            else:
                self.printIcmpCommunication(frame, self.icmpCount, True)
            

    def icmpPairAreCounted(self, frame: Frame, pair: int) -> bool:
        # if pair of ip addresses are in self.icmpFrames, return True
        if (frame.protocol["sourceIp"] in self.icmpFrames[pair]["ipPairs"] and frame.protocol["destIp"] in self.icmpFrames[pair]["ipPairs"]):
            return True
        else:
            return False


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
            print(frame.protocol["main"])

            if (frame.protocol["main"] == self.protocols["0800"]): # if IPv4
                print("zdrojova IP adresa: " + frame.protocol["sourceIp"])
                print("cielova IP adresa: " + frame.protocol["destIp"])
                print(frame.protocol["ipProtocol"])
                print("zdrojovy port: " + frame.protocol["sourcePort"])
                print("cielovy port: " + frame.protocol["destPort"])
            if (frame.protocol["main"] == self.protocols["0806"]): # if ARP
                if (frame.protocol["opcode"] == 1):
                    print("ARP - Request")
                else:
                    print("ARP - Reply")
                print("zdrojova IP adresa: " + frame.protocol["sourceIp"] + "\tcielova IP adresa: " + frame.protocol["destIp"])
                print("zdrojova MAC adresa: " + frame.protocol["sourceMac"] + "\tcielova MAC adresa: " + frame.protocol["destMac"])
                    
        print(hexdump(frame.data, True))
        print("")


    def printInfoToFile(self, frame: Frame):
        self.outputFile.write("ramec " + str(frame.number) + "\n")
        self.outputFile.write("dlzka ramca poskytnuta pcap API - " + str(frame.lenPcapApi) + " B" + "\n")
        self.outputFile.write("dlzka ramca prenasaneho po mediu - " + str(frame.lenPcapApi) + " B" + "\n")
        self.outputFile.write(frame.frameType + "\n")
        self.outputFile.write("zdrojova MAC adresa: " + frame.sourceMac + "\n")
        self.outputFile.write("cielova MAC adresa: " + frame.destMac + "\n")

        if (frame.protocol["main"] != None):
            self.outputFile.write(frame.protocol["main"]  + "\n")

            if (frame.protocol["main"] == self.protocols["0800"]): # if IPv4
                self.outputFile.write("zdrojova IP adresa: " + frame.protocol["sourceIp"] if "sourceIp" in  frame.protocol else "" + "\n")
                self.outputFile.write("cielova IP adresa: " + frame.protocol["destIp"] if "destIp" in  frame.protocol else "" + "\n")
                self.outputFile.write(frame.protocol["ipProtocol"] + "\n")
                try:
                    self.outputFile.write("zdrojovy port: " + frame.protocol["sourcePort"] if "sourcePort" in  frame.protocol else "" + "\n")
                    self.outputFile.write("cielovy port: " + frame.protocol["destPort"] if "destPort" in  frame.protocol else "" + "\n")
                except KeyError:
                    self.outputFile.write("zdrojovy port: \n")
                    self.outputFile.write("cielovy port: \n")
            # if (frame.protocol["main"] == self.protocols["0806"]): # if ARP
            #     if (frame.protocol["opcode"] == 1):
            #         self.outputFile.write("ARP - Request" + "\n")
            #     else:
            #         self.outputFile.write("ARP - Reply" + "\n")
            #     self.outputFile.write("zdrojova IP adresa: " + frame.protocol["sourceIp"] + "\tcielova IP adresa: " + frame.protocol["destIp"] + "\n")
            #     self.outputFile.write("zdrojova MAC adresa: " + frame.protocol["sourceMac"] + "\tcielova MAC adresa: " + frame.protocol["destMac"] + "\n")

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

    def printIcmpCommunication(self, frame: Frame, num: int, new: bool):
        if new:
            print("nova komunikacia c.: " + str(num))
        else:
            print("komunikacia c.: " + str(num))
        print("Typ: " + frame.protocol["msgType"] + "\tzdrojova ip: " + frame.protocol["sourceIp"] + "\tcielova ip: " + frame.protocol["destIp"])


    def printIcmpCommunicationToFile(self, frame: Frame, num: int, new: bool):
        if new:
            self.outputFile.write("nova komunikacia c.: " + str(num) + "\n")
        else:
            self.outputFile.write("komunikacia c.: " + str(num) + "\n")
        self.outputFile.write("Typ: " + frame.protocol["msgType"] + "\tzdrojova ip: " + frame.protocol["sourceIp"] + "\tcielova ip: " + frame.protocol["destIp"] + "\n\n")

    
    def printTcpUdpCommunication(self, frame: Frame, num: int, new: bool):
        if new:
            print("nova komunikacia c.: " + str(num))
        else:
            print("komunikacia c.: " + str(num))
        print(self.printFlags(frame))


    def printTcpUdpCommunicationToFile(self, frame: Frame, num: int, new: bool):
        if new:
            self.outputFile.write("nova komunikacia c.: " + str(num) + "\n")
        else:
            self.outputFile.write("komunikacia c.: " + str(num) + "\n")
        self.outputFile.write(self.printFlags(frame) + "\n\n")


    def printFlags(self, frame: Frame) -> str:
        if ("flagACK" not in frame.protocol.keys()):
            return ""
        flagACK = frame.protocol["flagACK"] 
        flagRST = frame.protocol["flagRST"]
        flagSYN = frame.protocol["flagSYN"]
        flagFIN = frame.protocol["flagFIN"]

        # ( (1) and not (0) )
        if ( (flagACK == 1) and (flagRST == 0 and flagSYN == 0 and flagFIN == 0) ):
            return "[ACK] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"] 
        elif ( (flagACK == 1 and flagRST == 1) and not (flagSYN == 0 and flagFIN == 0) ):
            return "[RST, ACK] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"] 
        elif ( (flagACK == 1 and flagSYN == 1) and not (flagRST == 0 and flagFIN == 0) ):
            return "[SYN, ACK] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"] 
        elif ( (flagACK == 1 and flagFIN == 1) and not (flagRST == 0 and flagSYN == 0) ):
            return "[FIN, ACK] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"]
        elif ( (flagRST == 1) and not (flagACK == 0 and flagSYN == 0 and flagFIN == 0) ):
            return "[RST] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"]
        elif ( (flagSYN == 1) and not (flagACK == 0 and flagRST == 0 and flagFIN == 0) ):
            return "[SYN] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"]
        elif ( (flagFIN == 1) and not (flagACK == 0 and flagRST == 0 and flagSYN == 0) ):
            return "[FIN] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"]
        else:
            return "[???] " + frame.protocol["sourcePort"] + " -> " + frame.protocol["destPort"]


    def checkFilter(self):
        if not (self.filteredProtocol in self.ports.values()):
            if (self.filteredProtocol and not self.filteredProtocol.isspace()):
                print(">>> Protocol " + self.filteredProtocol + " to filter not found.")
            self.filteredProtocol = None            



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
