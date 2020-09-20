import socket
import struct
import math
import sys
import time
import os
import threading
import flags as flag
from myException import CloseException



class SenderOld:
    # --------------------------------------------------
    # Init
    # --------------------------------------------------
    def __init__(self, host: str, port: int, packetSize: int):
        self.host = "127.0.0.1" if host is '' else host
        self.port = 5003 if port is '' else int(port)
        self.rawDataPacketSize = packetSize

        self.connectBool = False
        self.sendingBool = False
        self.keepAlive = True

        print("\nsender host: ", self.host)
        print("sender port: ", self.port)
        print("sender packet size: ", self.rawDataPacketSize)

        self.senderSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            self.init_connection()

        except CloseException:
            if not self.connectBool:
                intFlag = int((flag.FIN + flag.NONE).encode(), 2)
                finPacket = struct.pack(HEADER_FORMAT, 1, intFlag)
                self.senderSocket.sendto(finPacket, (self.host, self.port))

        except socket.timeout:
            print("TIMEOUT")
            flag.connectBool = False
            print("Closing connection...\nBye bye")

        except Exception as e:
            print("\n--------------------------------------------------")
            print("sender err:", e)
            print("--------------------------------------------------")

        finally:
            self.senderSocket.close()

    # --------------------------------------------------
    # Count amount of packets
    # --------------------------------------------------
    def get_num_of_packets(self, dataLen: int):
        count = 1
        while dataLen > self.rawDataPacketSize:
            dataLen = dataLen - self.rawDataPacketSize
            count += 1
        return count

    # --------------------------------------------------
    # Wait for answer and send corrupted
    # --------------------------------------------------
    def await_corrupted(self, packetsArr: list):
        self.senderSocket.settimeout(30)
        data = self.senderSocket.recvfrom(MAX_PACKET_SIZE)[0]
        self.senderSocket.settimeout(None)

        if data:
            (header), unpackedData = struct.unpack(HEADER_FORMAT, data[:5]), data[5:self.rawDataPacketSize + 1]
            # unpacked data contains numbers of corrupted packets
            strFlag = "{0:08b}".format(header[1])

            if strFlag[:4] == flag.CORRUPTED:
                for i in unpackedData.decode():
                    self.senderSocket.sendto(packetsArr[(int(i)-1)], (self.host, self.port))

    # --------------------------------------------------
    # Make the packets and send
    # --------------------------------------------------
    def make_packets_and_send(self, intFlag: int, data: bytes):
        numPackets = self.get_num_of_packets(len(data))
        numPacks = math.ceil(numPackets / PACKETS_PACK_SIZE)

        packetsArr = []

        rangeFrom = 0
        rangeTo = self.rawDataPacketSize

        for y in range(1, numPacks + 1):
            print(y, '. pack of packets')
            for x in range(1, (PACKETS_PACK_SIZE + 1)):
                print('sending ', x, '. packet')

                if (x == numPackets and numPackets != 1) or (x == (numPackets - PACKETS_PACK_SIZE) and y == numPacks):
                    # first 4 bytes indicates final packet
                    strFlag = "{0:08b}".format(intFlag)
                    strFlag = ''.join((strFlag[:0], flag.FIN_DATA, strFlag[4:]))
                    intFlag = int(strFlag.encode(), 2)

                dataPacket = struct.pack(HEADER_FORMAT, x, intFlag) + data[rangeFrom:rangeTo]
                print(dataPacket)
                self.senderSocket.sendto(dataPacket, (self.host, self.port))

                packetsArr.append(dataPacket)

                rangeFrom = rangeTo
                rangeTo = rangeTo + self.rawDataPacketSize

            self.await_corrupted(packetsArr)

            if y == numPacks:
                break

    # --------------------------------------------------
    # 3-way handshake or init connection
    # --------------------------------------------------
    def init_connection(self):
        print("Handshake...")
        try:
            print("Sending SYN packet...")
            intFlag = int((flag.SYN + flag.CRC_KEY).encode(), 2)
            CRC_polynomial = '0x8408'  # size 6
            firstPacket = struct.pack('=IB6sI', 1, intFlag, CRC_polynomial.encode(), int(self.packetSize))
            print("length of first packet:", len(firstPacket))

            self.senderSocket.sendto(firstPacket, (self.host, self.port))

            while True:
                print("Waiting for SYNACK packet...")
                self.senderSocket.settimeout(40)
                data, addr = self.senderSocket.recvfrom(self.packetSize)
                self.senderSocket.settimeout(None)

                if data:
                    unpackedData = struct.unpack('=IB', data)
                    print("Received SYNACK")
                    strFlag = "{0:08b}".format(unpackedData[1])

                    if strFlag[:4] == flag.SYN and strFlag[4:] == flag.ACK:
                        intFlag = int((flag.ACK + flag.NONE).encode(), 2)
                        ackPacket = struct.pack('=IB', 1, intFlag)
                        print("Sending ACK...")
                        self.senderSocket.sendto(ackPacket, (self.host, self.port))
                        break

            print("Handshake done\n\n")
            flag.connectBool = True

            # self.send()

        except UnicodeDecodeError as encodeErr:
            print("\nEncode err: ", encodeErr, "\n")
        except TypeError as typeErr:
            print("\nType err: ", typeErr, "\n")