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

class Client:
    # --------------------------------------------------
    # Init
    # --------------------------------------------------
    def __init__(self, selfIp: str, destIp: str, port: str, packetSize: int):
        self.selfIp = "127.0.0.1" if selfIp == "" or None else selfIp
        self.destIp = "127.0.0.1" if destIp == "" or None else destIp
        self.port = 5003 if port == "" or None else int(port)
        self.packetSize = packetSize
        
        self.clientSocket = None

        self.connectBool = False
        self.sendingBool = False
        self.keepAlive = True
        # print(self.selfIp, self.destIp, self.port, self.rawDataPacketSize)

        try: 
            self.initConnection()

        # except CloseException:
        #     if not self.connectBool:
        #         intFlag = int((flag.FIN + flag.NONE).encode(), 2)
        #         finPacket = struct.pack(HEADER_FORMAT, 1, intFlag)
        #         self.senderSocket.sendto(finPacket, (self.destIp, self.selfPort))

        except clientSocket.timeout:
            print("TIMEOUT")
            flag.connectBool = False
            print("Closing connection...\nBye bye")

        except Exception as e:
            print("\n--------------------------------------------------")
            print("client err:", e)
            print("--------------------------------------------------")

        finally:
            self.senderSocket.close()


    def initConnection(self):
        self.clientSocket = clientSocket.socket(clientSocket.AF_INET, clientSocket.SOCK_DGRAM)
        
        self.handshake()
        # poslat meta data - velkosti paketov, velkost balicku paketov
        
    def handshake(self):
        print("Handshake...")

        print("\tSending SYN packet...")
        charFlag = flagToChar(flag.SYN + flag.NONE)
        firstpacket = struct.pack(g.HEADER_FORMAT, 0, charFlag, 0)
        self.socket.sendto(firstpacket, (self.destIp, self.port))

        while True:
            print("\nWaiting for SYNACK packet...")
            self.clientSocket.settimeout(40)
            data, addr = self.clientSocket.recvfrom(self.packetSize)
            self.clientSocket.settimeout(None)

            if data:
                unpackedData = struct.unpack(g.HEADER_FORMAT, data)
                if validator.validateFlag(flag.SYN + flag.ACK, self.charToFlag(unpackedData[1])):
                    print("\tReceived SYNACK")


    def keepAlive(self):
        pass

    def flagToChar(self, flag: str):
        return chr(int((flag).encode(), 2))

    def charToFlag(self, char):
        return str(ord(char))


    

def main():
    # declare variables
    selfIp, destIp, port, packetSize = None, None, None, None

    # reading values
    while True:
        selfIp = input("\nZadaj svoju ip (lokalne nepovinne): ")
        if selfIp == "" or validator.validIp(selfIp):
            break
        else:
            print("ZLy format ip, skus znova\n")

    while True:
        destIp = input("Zadaj ip servera (lokalne nepovinne): ")
        if destIp == "" or validator.validIp(destIp):
            break
        else:
            print("ZLy format ip, skus znova\n")

    while True:
        port = input("Zadaj svoj port (nepovinne): ")
        if port == "" or validator.validPort(port):
            break
        else:
            print("ZLy port, skus znova\n")

    while True:
        packetSize = input("Zadaj maximalnu velkost paketu (" + str(g.HEADER_SIZE) + " - " + str(g.MAX_PACKET_SIZE) + "): ")
        if validator.validPacketSize(packetSize):
            break
        else:
            print("ZLa velkost, skus znova\n")

    # innitializing client
    client = Client(selfIp, destIp, port, int(packetSize))


if __name__ == "__main__":
    main()
