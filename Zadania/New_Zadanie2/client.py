import socket
import struct
import math
import time
import os
import threading
import flags as flag
import globalFile as g
import myExceptions as myExcep
import validators as validator


class Client:
# --------------------------------------------------
# Init
# --------------------------------------------------
    def __init__(self, serverIp: str, port: str, packetSize: int, err: str):
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.serverIp = "127.0.0.1" if serverIp == "l" else serverIp
        self.port = 13001 if port == "" or None else int(port)
        self.serverAddr = (self.serverIp, self.port)
        self.packetSize = packetSize
        self.err = True if err == "y" else False
        self.groupSize = 20

        self.keepAliveStatus = True
        self.keepAliveInterval = 10
        
        g.logger.info("Clien.init: { serverIp: " + self.serverIp + ", port: " + str(self.port) +  ", packetSize: " + str(self.packetSize) + ", groupSize: " + str(self.groupSize) + ", err: " + str(self.err) + " }")

        try: 
             self.handshake()

        # except CloseException:
        #     if not self.connectBool:
        #         intFlag = int((flag.FIN + flag.NONE).encode(), 2)
        #         finPacket = struct.pack(HEADER_FORMAT, 1, intFlag)
        #         self.senderSocket.sendto(finPacket, (self.destIp, self.selfPort))

        except socket.timeout:
            print("\n---TIMEOUT---\n")
            flag.connectBool = False
            
        # except Exception as e:
        #     print(str(e))
        #     g.logger.error("Client.error: " + str(e))

        finally:
            print("Closing connection...\nBye bye")
            self.clientSocket.close()
            g.logger.info("Client.close: connection closed with server")


# --------------------------------------------------
# Class functions
# --------------------------------------------------     
    def handshake(self):
        print("Handshake...")
        print("\tSending SYN packet...")
        
        data = bytearray((self.packetSize, self.groupSize)) # metadata = size of packets and size of packs of packets
        packet = struct.pack(g.HEADER_FORMAT, 0, self.flagToChar(flag.SYN + flag.METADATA), 0) + data
        
        self.clientSocket.sendto(packet, self.serverAddr)
        self.clientSocket.settimeout(40)
        
        g.logger.info("Client.send: " + str(packet))

        while True:
            print("\tWaiting for SYNACK packet...")
            data, addr = self.clientSocket.recvfrom(self.packetSize)
            # self.clientSocket.settimeout(None)

            if data:
                unpackedData = struct.unpack(g.HEADER_FORMAT, data)
                g.logger.info("Client.recv: " + str(unpackedData))
                
                if validator.validateFlag(flag.SYN + flag.ACK, self.charToFlag(unpackedData[1])):
                    print("\tReceived SYNACK packet")
                    print("\tSending ACK...")

                    packet = struct.pack(g.HEADER_FORMAT, 0, flagToChar(flag.SYN + flag.NONE), 0)
                    
                    self.clientSocket.sendto(packet, self.serverAddr)

                    g.logger.info("Client.send: " + str(packet))
                    break
        
        print("Handshake done\n\n")


    def keepAlive(self):
        # refactor
        while True:
            if not self.keepAliveStatus:
                return
            packetKA = struct.pack(g.HEADER_FORMAT, 0, flagToChar(flag.SYN + flag.KEEP_ALIVE), 0)
            self.clientSocket.sendto(packetKA, (self.destIp, self.selfPort))
            g.logger.info("~~~~~ Keep alive")
            time.sleep(self.keepAliveInterval)


    def startKeepAliveThread(self):
        thread = threading.Thread(target = self.keepAlive, daemon=True)
        thread.start()
        return thread


    def flagToChar(self, flag: str) -> int:
        return int(flag)


    def charToFlag(self, char: int):
        return str(char)
