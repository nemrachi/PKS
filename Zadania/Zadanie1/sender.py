import socket
import struct
import flags as flag
import os
from myException import CloseException
import threading
import sys
import time

MAX_PACKET_SIZE = 1487  # bytes
BAG_PACKETS = 10


class Sender:
    # --------------------------------------------------
    # Init
    # --------------------------------------------------
    def __init__(self, host, port, packetSize):
        if host is '':
            self.host = "127.0.0.1"
        else:
            self.host = host

        if port is '':
            self.port = 5003
        else:
            self.port = int(port)

        if MAX_PACKET_SIZE != packetSize:
            self.packetSize = packetSize + 13
            # 13 because of 8B UDP header, 5B my header
            # packetSize from user is for raw data
        else:
            self.packetSize = MAX_PACKET_SIZE

        self.sendingBool = False
        self.connectBool = False

        print("\nsender host: ", self.host)
        print("sender port: ", self.port)
        print("sender packet size: ", self.packetSize)

        self.senderSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            self.sender_process()

        except CloseException:
            if not self.connectBool:
                intFlag = int((flag.FIN + flag.NONE).encode(), 2)
                firstPacket = struct.pack('=IBI', 1, intFlag, 1)
                self.senderSocket.sendto(firstPacket, (self.host, self.port))
            print("Closing connection...\nBye bye")

        except socket.timeout:
            print("TIMEOUT")
            print("Closing connection...\nBye bye")

        except Exception as e:
            print("\n--------------------------------------------------")
            print("sender err:", e)
            print("--------------------------------------------------")

        finally:
            self.senderSocket.close()

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
            self.connectBool = True

            # self.send()

        except UnicodeDecodeError as encodeErr:
            print("\nEncode err: ", encodeErr, "\n")
        except TypeError as typeErr:
            print("\nType err: ", typeErr, "\n")

    # --------------------------------------------------
    # Count amount of packets
    # --------------------------------------------------
    def get_num_of_packets(self, dataLen):
        count = 1
        while dataLen > (self.packetSize - 13):
            dataLen = dataLen - (self.packetSize - 13)
            count += 1
        return count

    # --------------------------------------------------
    # Keep alive receiver
    # --------------------------------------------------
    def keep_alive(self):
        while not self.sendingBool:
            # do keep alive
            print("Sending keep alive packet...")
            intFlag = int((flag.SYN + flag.KEEP_ALIVE).encode(), 2)
            kaPacket = struct.pack('=IBI', 1, intFlag, 1)
            self.senderSocket.sendto(kaPacket, (self.host, self.port))

            self.senderSocket.settimeout(10)
            data, addr = self.senderSocket.recvfrom(self.packetSize)
            self.senderSocket.settimeout(None)

            if data:
                unpackedData = struct.unpack('=IB', data)
                strFlag = "{0:08b}".format(unpackedData[1])
                if strFlag[:4] == flag.ACK:
                    print("\tReceiver -> I am still alive")
            time.sleep(20)

    # --------------------------------------------------
    # Interrupt keep alive
    # --------------------------------------------------

    def interrupt_keep_alive(self):
        interruptInput = input('Enter anything to interrupt keep alive and start sending')
        self.sendingBool = True

    def sending_message(self):
        msgInput = input("Message: ")

        intFlag = int((flag.METADATA + flag.STRING).encode(), 2)
        numPackets = self.get_num_of_packets(len(msgInput))
        metadataPacket = struct.pack('=IBI', 1, intFlag, numPackets)
        print("\nnumber of packets:", numPackets, "\n")
        print("Sending message...")

        self.senderSocket.sendto(metadataPacket, (self.host, self.port))

        while self.sendingBool:
            print("Waiting for ACK...")
            self.senderSocket.settimeout(40)
            data, addr = self.senderSocket.recvfrom(self.packetSize)

            if data:
                print("Received ACK")
                unpackedData = struct.unpack('=IB', data)
                strFlag = "{0:08b}".format(unpackedData[1])

                # tuto bude aj else, kde bude zachytavat chybajuce packety alebo poskodene
                if strFlag[:4] == flag.ACK:
                    msgInput = msgInput.encode()
                    rangeFrom = 0
                    rangeTo = self.packetSize - 13

                    # upravit v receiverovi!!!!!
                    for x in range(1, numPackets + 1):
                        if x == numPackets:
                            intFlag = int((flag.FIN_DATA + flag.STRING).encode(), 2)
                        elif x == 1:
                            intFlag = int((flag.SYN_DATA + flag.STRING).encode(), 2)
                        else:
                            intFlag = int((flag.DATA + flag.STRING).encode(), 2)
                        print('sending ', x, '. packet')
                        msgDataPacket = struct.pack('=IB', x, intFlag) + msgInput[rangeFrom:rangeTo]
                        print(msgDataPacket)
                        self.senderSocket.sendto(msgDataPacket, (self.host, self.port))

                        rangeFrom = rangeTo
                        rangeTo = rangeTo + (self.packetSize - 13)
                    break

        print("\nMessage send\n")

        # user si moze vybrat, ci chce dalej posielat alebo posielat keep alive, ale ak nezareaguje do 40 sekund, server sa vypne

    # --------------------------------------------------
    # Sending keep alive or files or closing packet
    # --------------------------------------------------
    def send(self):
        interruptThread = threading.Thread(target=self.interrupt_keep_alive)
        interruptThread.start()

        self.keep_alive()

        while self.sendingBool:
            # waiting for input from user
            print("Do you want to send file or exit connection ?")
            print("\ts - send file\n\te - exit")
            userInput = input()

            if userInput == 's':
                pass
            elif userInput == 'e':
                self.connectBool = False
                raise CloseException
            else:
                print("Please choose 's' or 'c'")
                continue

            print("Do you want to send message or file:")
            print("\tm - message\n\tf - file")
            userInput = input()

            # --------------------------------------------------
            # Message
            # --------------------------------------------------
            if userInput == 'm':
                self.sending_message()

            # --------------------------------------------------
            # File
            # --------------------------------------------------
            elif userInput == 'f':
                while 1:
                    pathInput = input("Path to file: ")
                    if not (os.path.exists(pathInput)):
                        continue
                splitted = pathInput.split('\\')
                fileName = splitted[len(splitted) - 1]
                splitted = fileName.split('.')
                fileType = splitted[1]
                print('fileType:', fileType)

                intFlag = int((flag.METADATA + flag.NONE).encode(), 2)

                if fileType == 'jpg' or fileType == 'jpeg' or fileType == 'gif' or fileType == 'png':
                    intFlag = int((flag.METADATA + flag.IMG_FILE).encode(), 2)
                elif fileType == 'txt' or fileType == 'pdf' or fileType == 'docx' or fileType == 'c' or fileType == 'py' or fileType == 'java':
                    intFlag = int((flag.METADATA + flag.TXT_FILE).encode(), 2)
                elif fileType == 'mp3' or fileType == 'flac':
                    intFlag = int((flag.METADATA + flag.SOUND_FILE).encode(), 2)
                elif fileType == 'mp4':
                    intFlag = int((flag.METADATA + flag.VIDEO_FILE).encode(), 2)
                elif fileType == 'exe':
                    intFlag = int((flag.METADATA + flag.EXE_FILE).encode(), 2)
                else:
                    print('Nepoznam file')

                inputFile = open(pathInput, 'r+b')
                inputFile = inputFile.read()  # toto mi capne do binary

                # v tomto packete poslem pocet packetov a co to je za typ(to je v hlavicke - flag)
                numPackets = self.get_num_of_packets(os.path.getsize(inputFile))

                metadataPacket = struct.pack('=IBI', 1, intFlag, numPackets)
                print("metadata packet:", metadataPacket)
                print("num of packets:", numPackets, "\n")

                self.senderSocket.sendto(metadataPacket, (self.host, self.port))

                while True:
                    print("Waiting for ACK...")
                    self.senderSocket.settimeout(40)
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
                            for x in range(1, numPackets + 1):
                                print('sending ', x, '. packet')
                                msgDataPacket = struct.pack('=IB', x, intFlag) + msgInput[rangeFrom:rangeTo]
                                print(msgDataPacket)
                                self.senderSocket.sendto(msgDataPacket, (self.host, self.port))

                                rangeFrom = rangeTo
                                rangeTo = rangeTo + self.packetSize
                            break

                print("\nMessage send\n")

            # --------------------------------------------------
            # Something else
            # --------------------------------------------------
            else:
                print("Please choose 'm' or 'f'")

    def sender_process(self):
        self.init_connection()

        if self.connectBool:
            self.send()
