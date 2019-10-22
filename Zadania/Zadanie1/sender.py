import socket
import struct
import flags as flag
import binascii
# ctypes is imported to create a string buffer
import ctypes
import sys
import threading
import time

MAX_PACKET_SIZE = 1487  # bytes
HEADER_FORMAT = '=IB'


class Sender:
    port = 5003

    def __init__(self, host="127.0.0.1", packetSize=MAX_PACKET_SIZE):
        self.host = host
        self.packetSize = packetSize  # bytes
        print("sender packet size set: ", self.packetSize)
        print("sender host: ", self.host, "\n")

        self.senderSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.init_connection()

    def init_connection(self):
        try:
            print("Sending first packet...")
            intFlag = int((flag.SYN + flag.CRC_KEY).encode(), 2)
            CRC_polynomial = '11000000000000101'  # 17

            firstPacket = struct.pack('=IB17sI', 1, intFlag, CRC_polynomial.encode(), int(self.packetSize))
            print("first packet:", firstPacket)
            print("length of packet:", len(firstPacket), "\n")

            self.senderSocket.sendto(firstPacket, (self.host, self.port))

            while True:
                print("Waiting for SYNACK")
                data, addr = self.senderSocket.recvfrom(self.packetSize)

                if data:
                    unpackedData = struct.unpack('=IB', data)
                    print("Received SYNACK: ", unpackedData)
                    strFlag = "{0:08b}".format(unpackedData[1])
                    print("flag:", strFlag, "\n")
                    if strFlag[:4] == flag.SYN:
                        if strFlag[4:] == flag.ACK:
                            intFlag = int((flag.ACK + flag.NONE).encode(), 2)
                            ackPacket = struct.pack('=IB', 1, intFlag)
                            print("Sending ACK...")
                            self.senderSocket.sendto(ackPacket, (self.host, self.port))
                            break

            print("\nHandshake done\n")

            self.easy_sending_one_file()

        except UnicodeDecodeError as encodeErr:
            print("Encode err: ", encodeErr)
        except TypeError as typeErr:
            print("Type err: ", typeErr)
        except:
            print("Unexpected error:", sys.exc_info()[0])
            raise

    # def input_from_user(self):
    #     count = 0
    #     while True:
    #         print("Ich bin waiting for input")
    #         count += 1
    #         if count == 6:
    #             print("User inputol")
    #             break
    #
    #
    # def keep_alive(self):
    #     while True:
    #         print("Alive")
    #
    #
    # def body_with_2_threads(self):

    def get_num_of_packets(self, dataLen):
        count = 1

        while dataLen > self.packetSize:
            dataLen = dataLen - self.packetSize
            count += 1

        return count

    def easy_sending_one_file(self):
        print("Do you want to send message or file:")
        print("\tm - message\n\tf - file")
        userInput = input()
        # --------------------------------------------------
        # Message
        # --------------------------------------------------
        if userInput == 'm':
            msgInput = input("Napis par teplych slov: ")

            intFlag = int((flag.METADATA + flag.STRING).encode(), 2)
            # v tomto packete poslem pocet packetov a co to je za typ(to je v hlavicke - flag)
            numPackets = self.get_num_of_packets(len(msgInput))

            metadataPacket = struct.pack('=IBI', 1, intFlag, numPackets)
            print("metadata packet:", metadataPacket)
            print("num of packets:", numPackets, "\n")

            self.senderSocket.sendto(metadataPacket, (self.host, self.port))

            while True:
                print("Waiting for ACK...")
                data, addr = self.senderSocket.recvfrom(self.packetSize)

                if data:
                    unpackedData = struct.unpack('=IB', data)
                    print("Received ACK: ", unpackedData)
                    strFlag = "{0:08b}".format(unpackedData[1])
                    print("flag:", strFlag, "\n")

                    if strFlag[:4] == flag.ACK:
                        msgInput = msgInput.encode()
                        intFlag = int((flag.DATA + flag.STRING).encode(), 2)

                        rangeFrom = 0
                        rangeTo = self.packetSize
                        for x in range(1, numPackets+1):
                            print('sending ', x, '. packet')
                            msgDataPacket = struct.pack('=IB', x, intFlag) + msgInput[rangeFrom:rangeTo]
                            print(msgDataPacket)
                            self.senderSocket.sendto(msgDataPacket, (self.host, self.port))

                            rangeFrom = rangeTo
                            rangeTo = rangeTo + self.packetSize
                        break

            print("\nMessage send\n")

        # --------------------------------------------------
        # File
        # --------------------------------------------------
        elif userInput == 'f':
            print("user choose m")

        # --------------------------------------------------
        # Something else
        # --------------------------------------------------
        else:
            print("user choose something else")
