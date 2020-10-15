import socket
import struct
import math
import sys
import time
import os
import _thread
import flags as flag
import globalFile as g
import myExceptions as myExcep
import validators as validator

class Server:
# --------------------------------------------------
# Init
# --------------------------------------------------
    def __init__(self, ip: str, port: str):
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.ip = "127.0.0.1" if ip == "l" else socket.gethostbyname(socket.gethostname())
        self.port = 13001 if port == "" or None else int(port)
        self.packetSize = 1000
        self.groupSize = 0

        g.logger.info("Server.init: { ip: " + self.ip + ", port: " + str(self.port) + " }")

        try:
            self.serverSocket.bind(("", self.port))
            self.handshake()

        except socket.timeout:
            print("\n---TIMEOUT---\n")
            flag.connectBool = False


# --------------------------------------------------
# Class functions
# --------------------------------------------------     
    def handshake(self):
        print("Handshake...")
        data, addr = self.serverSocket.recvfrom(self.packetSize)
        self.serverSocket.settimeout(40)

        if data:
            header, unpackedData =  struct.unpack(g.HEADER_FORMAT, data[:9]), data[9:]
            g.logger.info("Server.recv: " + str(unpackedData))

            if validator.validateFlag(flag.SYN + flag.METADATA, self.charToFlag(unpackedData[1])):
                print(unpackedData)
                packet = struct.pack(g.HEADER_FORMAT, 0, flagToChar(flag.SYN + flag.ACK), 0)
                self.socket.sendto(packet, (self.destIp, self.port))

        print("Handshake done\n\n")



    def flagToChar(self, flag: str) -> int:
        return int(flag)


    def charToFlag(self, char: int):
        return str(char)
