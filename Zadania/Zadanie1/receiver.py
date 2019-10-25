import socket
import struct
import math
from myException import CloseException
import traceback

import flags as flag
import time
import sys
import threading


INIT_PACKET_SIZE = 15
HEADER_FORMAT = '=IB'


class Receiver:
    # --------------------------------------------------
    # Init
    # --------------------------------------------------
    def __init__(self, port):
        self.host = "127.0.0.1"
        # toto odkomentovat pred odovzdanim !!!!!!!!!!!!!!!!!!!!!
        # self.hostName = socket.gethostname()
        # self.host = socket.gethostbyname(self.hostName)

        if port is '':
            self.port = 5003
        else:
            self.port = int(port)

        self.packetSize = INIT_PACKET_SIZE
        self.CRC_key = ''
        self.senderInfo = None
        self.receivingBool = False
        flag.connectBool = False

        print("\nreceiver packet size set:", self.packetSize)
        print("receiver host:", self.host)

        self.receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            self.receiver_process()

        except CloseException:
            print("Receiver closing connection...\nBye bye")
            flag.connectBool = False

        except socket.timeout:
            print("TIMEOUT")
            flag.connectBool = False
            print("Receiver closing connection...\nBye bye")

        except Exception as e:
            print("\n--------------------------------------------------")
            print("receiver err:", e)
            print("--------------------------------------------------")

        finally:
            # vo while v receive dam timeout a ak prejde, breakne ho
            self.receiverSocket.close()

    def handshake(self):
        self.receiverSocket.bind((self.host, self.port))

        while True:
            # tuple data(bytes) and addr - tuple (ip of sender, port of sender)
            self.receiverSocket.settimeout(40)
            data, addr = self.receiverSocket.recvfrom(self.packetSize)
            self.receiverSocket.settimeout(None)

            if data:
                self.senderInfo = addr

                print("Received SYN packet with CRC")
                unpackedData = struct.unpack('=IB6sI', data)
                strFlag = "{0:08b}".format(unpackedData[1])

                if strFlag[:4] == flag.SYN and strFlag[4:] == flag.CRC_KEY:
                    self.CRC_key = unpackedData[2]
                    print("CRC polynomial:", self.CRC_key)
                    self.packetSize = unpackedData[3]
                    print("packet size set:", self.packetSize, "\n")

                    print("Sending SYNACK packet...")
                    intFlag = int((flag.SYN + flag.ACK).encode(), 2)
                    synackPacket = struct.pack('=IB', 1, intFlag)
                    # print("tuple with addr of sender:", self.senderInfo)
                    self.receiverSocket.sendto(synackPacket, self.senderInfo)

                    while True:
                        print("Waiting for ACK...")
                        self.receiverSocket.settimeout(40)
                        data, addr = self.receiverSocket.recvfrom(self.packetSize)
                        self.receiverSocket.settimeout(None)

                        if data:
                            print("Received  ACK")
                            unpackedData = struct.unpack('=IB', data)
                            strFlag = "{0:08b}".format(unpackedData[1])
                            if strFlag[:4] == flag.ACK:
                                break

            break

        print("Handshake done\n\n")

        # self.receive()

    def receive(self):
        # receive metadata or keep-alive packet or closing packet
        print("\n\tAfter successful handshake starting receiving\n")

        while flag.connectBool:
            self.receiverSocket.settimeout(60)
            data, addr = self.receiverSocket.recvfrom(self.packetSize)
            self.receiverSocket.settimeout(None)

            if data:
                unpackedData = struct.unpack('=IBI', data)
                strFlag = "{0:08b}".format(unpackedData[1])

                if strFlag[:4] == flag.SYN_DATA and strFlag[4:] == flag.NONE:
                    self.receiverSocket.settimeout(60)
                    data, addr = self.receiverSocket.recvfrom(self.packetSize)
                    self.receiverSocket.settimeout(None)

                    if data:
                        unpackedData = struct.unpack('=IBI', data)
                        strFlag = "{0:08b}".format(unpackedData[1])

                        bagEnd = 0
                        corruptedPacketsNum = ''

                        if strFlag[:4] == flag.METADATA:  # toto treba skontrolovat a prerobit

                            print("\nReceived metadata for...")
                            numPackets = unpackedData[2]
                            intFlag = int((flag.ACK + flag.NONE).encode(), 2)
                            ackPacket = struct.pack('=IB', 1, intFlag)
                            self.receiverSocket.sendto(ackPacket, self.senderInfo)

                            if strFlag[4:] == flag.STRING:
                                print("...string")
                                print('number of packets:', numPackets)

                                numOfBags = math.ceil(numPackets / 10)
                                controlArr = [0] * numPackets
                                wholeData = ''

                                while flag.connectBool:
                                    self.receiverSocket.settimeout(60)
                                    data = self.receiverSocket.recvfrom(self.packetSize)[0]
                                    self.receiverSocket.settimeout(None)

                                    if data:
                                        (header), unpackedData = struct.unpack('=IB', data[:5]), data[
                                                                                                 5:self.packetSize + 1]
                                        strFlag = "{0:08b}".format(header[1])

                                        if strFlag[:4] == flag.SYN_DATA or strFlag[:4] == flag.DATA:
                                            wholeData = wholeData + unpackedData.decode()
                                            controlArr[(header[0] - 1)] = 1
                                            continue

                                        elif strFlag[:4] == flag.FIN_DATA:
                                            wholeData = wholeData + unpackedData.decode()
                                            controlArr[(header[0] - 1)] = 1
                                            bagEnd = header[0]

                                        while True:
                                            if bagEnd == 10 or bagEnd == numPackets:
                                                for i in range(len(controlArr)):
                                                    if controlArr[i] == 0:
                                                        corruptedPacketsNum = corruptedPacketsNum + str(i + 1)

                                                intFlag = int((flag.ACK + flag.CORRUPTED).encode(), 2)
                                                ackPacket = struct.pack('=IB', 1, intFlag) + corruptedPacketsNum
                                                self.receiverSocket.sendto(ackPacket, (self.host, self.port))

                                                while flag.connectBool:
                                                    self.receiverSocket.settimeout(60)
                                                    data = self.receiverSocket.recvfrom(self.packetSize)[0]
                                                    self.receiverSocket.settimeout(None)

                                                    if data:

                                        continue




                                for y in range(1, numOfBags + 1):
                                    print(y, '. bag of packets')
                                    for x in range(1, (10 + 1)):
                                        if x == numPackets + 1:
                                            break
                                        print(x, '. packet')
                                        data, addr = self.receiverSocket.recvfrom(self.packetSize)
                                        if not data:
                                            break
                                        (header), unpackedData = struct.unpack('=IB', data[:5]), data[
                                                                                                 5:self.packetSize + 1]
                                        wholeData = wholeData + unpackedData.decode()
                                        controlArr[(header[0] - 1)] = 1
                                        print(header)
                                        print(unpackedData)

                                    print(controlArr)
                                    if y == numOfBags:
                                        break

                                print("Received message: ", wholeData)
                                continue
                            else:
                                print('tu budu files')

                elif strFlag[:4] == flag.SYN and strFlag[4:] == flag.KEEP_ALIVE:
                    print('\nI am still alive')
                    intFlag = int((flag.ACK + flag.NONE).encode(), 2)
                    ackPacket = struct.pack('=IB', 1, intFlag)
                    self.receiverSocket.sendto(ackPacket, self.senderInfo)

                elif strFlag[:4] == flag.FIN:
                    raise CloseException

                else:
                    continue

    def receiver_process(self):
        self.handshake()

        if flag.connectBool:
            self.receive()
