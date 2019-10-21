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
INIT_PACKET_SIZE = 20  # bytes
HEADER_FORMAT = '=IB'


class Sender:
    port = 5003

    def __init__(self, host="127.0.0.1", packetSize=MAX_PACKET_SIZE):
        self.host = host
        self.packetSize = packetSize  # bytes
        print("sender packet size set: ", self.packetSize)
        print("sender host: ", self.host, "\n\n")

        self.senderSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.init_connection()

    def set_packet_header(self, packetFlag, dataSizeBits):
        packetLen = dataSizeBits + (struct.calcsize(HEADER_FORMAT) * 8) + 64  # bits
        count = 1

        while packetLen > (self.packetSize*8):
            packetLen = packetLen - self.packetSize
            count = count + 1

        packetHeader = struct.pack(HEADER_FORMAT, count, packetFlag)
        print("packet header:", packetHeader)
        return packetHeader

    def init_connection(self):
        try:
            print("Sending first packet...")
            intFlag = int((flag.SYN + flag.CRC_KEY).encode(), 2)
            CRC_polynomial = '11000000000000101'  # 17

            firstPacket = struct.pack('=IB17sI', 1, intFlag, CRC_polynomial.encode(), self.packetSize)
            print("first packet:", firstPacket)
            print("length of packet:", len(firstPacket), "\n\n")

            self.senderSocket.sendto(firstPacket, (self.host, self.port))

            while True:
                print("Waiting for SYNACK")
                data, addr = self.senderSocket.recvfrom(self.packetSize)

                if data:
                    unpackedData = struct.unpack('=IB', data)
                    print("Received SYNACK: ", unpackedData)
                    strFlag = "{0:08b}".format(unpackedData[1])
                    print("flag:", strFlag, "\n\n")
                    if strFlag[:4] == flag.SYN:
                        if strFlag[4:] == flag.ACK:
                            intFlag = int((flag.ACK + flag.NONE).encode(), 2)
                            ackPacket = struct.pack('=IB', 1, intFlag)
                            print("Sending ACK...")
                            self.senderSocket.sendto(ackPacket, (self.host, self.port))
                            break

            print("Handshake done")

        except UnicodeDecodeError as encodeErr:
            print("Encode err: ", encodeErr)
        except TypeError as typeErr:
            print("Type err: ", typeErr)
        except:
            print("Unexpected error:", sys.exc_info()[0])
            raise
