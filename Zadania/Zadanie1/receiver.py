import socket
import struct
import flags as flag
import time
import sys
import threading


class Receiver:
    port = 5003

    def __init__(self, host="127.0.0.1"):
        self.host = host
        self.packetSize = 26
        self.CRC_key = ''
        print("receiver packet size set:", self.packetSize)
        print("receiver host:", self.host, "\n")

        self.receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.handshake()

    def handshake(self):
        self.receiverSocket.bind((self.host, self.port))

        while True:
            # tuple data(bits) and addr - tuple (ip from sender, port of sender)
            data, addr = self.receiverSocket.recvfrom(self.packetSize)

            if data:
                print("Received SYN with CRC")
                unpackedData = struct.unpack('=IB17sI', data)
                print("unpacked: ", unpackedData)
                strFlag = "{0:08b}".format(unpackedData[1])
                print("flag:", strFlag)

                if strFlag[:4] == flag.SYN:
                    if strFlag[4:] == flag.CRC_KEY:
                        self.CRC_key = unpackedData[2]
                        print("CRC from received data:", self.CRC_key)

                    self.packetSize = unpackedData[3]
                    print("receiver packet size:", self.packetSize, "\n")

                    print("sending SYNACK packet...")
                    intFlag = int((flag.SYN + flag.ACK).encode(), 2)
                    synackPacket = struct.pack('=IB', 1, intFlag)
                    print("tuple with addr of sender:", addr)
                    self.receiverSocket.sendto(synackPacket, addr)
                    print("SYNACK packet:", synackPacket, "\n")

                    while True:
                        data, addr = self.receiverSocket.recvfrom(self.packetSize)

                        if data:
                            print("Received  ACK...")
                            unpackedData = struct.unpack('=IB', data)
                            strFlag = "{0:08b}".format(unpackedData[1])
                            print("flags received ACK:", strFlag)

                            if strFlag[:4] == flag.ACK:
                                print("YAY")
                                break

                inputing = input("End it?")
                if inputing is '':
                    break
