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
        self.connectBool = False

        print("\nreceiver packet size set:", self.packetSize)
        print("receiver host:", self.host)

        self.receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            self.receiver_process()

        except CloseException:
            print("Receiver closing connection...\nBye bye")

        except socket.timeout:
            print("TIMEOUT")
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
        self.connectBool = True

        # self.receive()

    def receive(self):
        # receive metadata or keep-alive packet or closing packet
        print("\n\tAfter successful handshake starting receiving\n")

        while self.connectBool:
            self.receiverSocket.settimeout(60)
            data, addr = self.receiverSocket.recvfrom(self.packetSize)
            self.receiverSocket.settimeout(None)

            if data:
                unpackedData = struct.unpack('=IBI', data)
                strFlag = "{0:08b}".format(unpackedData[1])

                if strFlag[:4] == flag.METADATA:  # toto treba skontrolovat a prerobit

                    print("\nReceived metadata for...")
                    numPackets = unpackedData[2]

                    if strFlag[4:] == flag.STRING:
                        print("...string")
                        print('number of packets:', numPackets)

                        intFlag = int((flag.ACK + flag.NONE).encode(), 2)
                        ackPacket = struct.pack('=IB', 1, intFlag)
                        self.receiverSocket.sendto(ackPacket, self.senderInfo)

                        numOfBags = math.ceil(numPackets / 10)
                        print(numOfBags)

                        controlArr = [0] * numPackets

                        wholeData = ''

                        for y in range(1, numOfBags + 1):
                            print(y, '. bag of packets')
                            for x in range(1, (10 + 1)):
                                if x == numPackets + 1:
                                    break
                                print(x, '. packet')
                                data, addr = self.receiverSocket.recvfrom(self.packetSize)
                                if not data:
                                    break
                                (header), unpackedData = struct.unpack('=IB', data[:5]), data[5:self.packetSize + 1]
                                wholeData = wholeData + unpackedData.decode()
                                controlArr[(header[0] - 1)] = 1
                                print(header)
                                print(unpackedData)

                            print(controlArr)
                            if y == numOfBags:
                                break

                        print("Received message: ", wholeData)
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

        if self.connectBool:
            self.receive()
