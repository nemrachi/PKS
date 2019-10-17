import socket
import packetHeader as pH
import flags as flag
import sys
import threading


host = "127.0.0.1"  # localhost
port = 3003
senderSocket = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP


def convert_str_to_bin(strBin):
    return bin(int(strBin))


def init_connection():
    try:
        packetHeader = pH.set_header(1, convert_str_to_bin(flag.SYN + flag.CRC_KEY))
        CRC_polynomial = '11000000000000101'
        packet = packetHeader + CRC_polynomial

        senderSocket.sendto(packet.encode(), (host, port))
    except UnicodeDecodeError as encodeErr:
        print(encodeErr)


def send(message):
    # print("UDP target IP:", host)
    # print("UDP target port:", port)
    init_connection()
    print("sending message:", message)
    senderSocket.sendto(message.encode(), (host, port))  # STR.encode() - zmeni str na bajty
