import socket
import struct
import traceback

import flags as flag
import time
import sys
import threading

INIT_PACKET_SIZE = 26  # bytes
HEADER_FORMAT = '=IB'


class Receiver:
    port = 5003

    def __init__(self, host="127.0.0.1"):
        self.host = host
        self.packetSize = INIT_PACKET_SIZE
        self.CRC_key = ''
        self.senderInfo = None
        print("receiver packet size set:", self.packetSize)
        print("receiver host:", self.host, "\n")

        self.receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.handshake()

    def handshake(self):
        self.receiverSocket.bind((self.host, self.port))

        while True:
            # tuple data(bytes) and addr - tuple (ip of sender, port of sender)
            data, addr = self.receiverSocket.recvfrom(self.packetSize)

            if data:
                self.senderInfo = addr

                print("Received SYN with CRC")
                unpackedData = struct.unpack('=IB17sI', data)
                print("unpacked: ", unpackedData)
                strFlag = "{0:08b}".format(unpackedData[1])
                print("flag:", strFlag)

                if strFlag[:4] == flag.SYN:
                    if strFlag[4:] == flag.CRC_KEY:
                        self.CRC_key = unpackedData[2]
                        print("CRC from received data:", self.CRC_key)

                    self.packetSize = unpackedData[3] + 13
                    print("receiver packet size:", self.packetSize, "\n")

                    print("sending SYNACK packet...")
                    intFlag = int((flag.SYN + flag.ACK).encode(), 2)
                    synackPacket = struct.pack('=IB', 1, intFlag)
                    print("tuple with addr of sender:", self.senderInfo)
                    self.receiverSocket.sendto(synackPacket, self.senderInfo)
                    print("SYNACK packet:", synackPacket, "\n")

                    while True:
                        data, addr = self.receiverSocket.recvfrom(self.packetSize)

                        if data:
                            print("Received  ACK...")
                            unpackedData = struct.unpack('=IB', data)
                            strFlag = "{0:08b}".format(unpackedData[1])
                            print("flags received ACK:", strFlag)

                            if strFlag[:4] == flag.ACK:
                                print("YAY\n")
                                break

                self.receive()

    def receive(self):
        # first metadata
        while True:
            data, addr = self.receiverSocket.recvfrom(self.packetSize)

            if data:
                self.senderInfo = addr

                print("Received metadata")
                unpackedData = struct.unpack('=IBI', data)
                print("unpacked: ", unpackedData)
                strFlag = "{0:08b}".format(unpackedData[1])
                print("flag:", strFlag)
                numPackets = unpackedData[2]

                if strFlag[:4] == flag.METADATA:
                    if strFlag[4:] == flag.STRING:
                        print("\nreceiver will be getting string")

                        intFlag = int((flag.ACK + flag.NONE).encode(), 2)
                        ackPacket = struct.pack('=IB', 1, intFlag)
                        self.receiverSocket.sendto(ackPacket, self.senderInfo)

                        try:
                            for x in range(1, (numPackets + 1)):
                                print(x, '. packet')
                                data, addr = self.receiverSocket.recvfrom(self.packetSize)
                                (header), unpackedData = struct.unpack('=IB', data[:5]), data[5:self.packetSize+1]
                                print(header)
                                print(unpackedData)
                        except socket.timeout:
                            print(socket.timeout)
                    else:
                        print('tu bude nieco druhe')
                break
