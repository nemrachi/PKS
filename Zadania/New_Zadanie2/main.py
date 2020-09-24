import os
import globalFile as g
import validators as validator
from client import Client
from server import Server

# python main.py
def main():
    while True:
        role = input("Chces byt klient(c) alebo server(s)?\n")
        if role == "c":
            clientStart()
            break
        elif role == "s":
            serverStart()
            break
        else:
            print("Zly input\n")

def clientStart():
    # declare variables
    serverIp, port, packetSize, err = None, None, None, None

    # reading values
    while True:
        serverIp = input("Zadaj ip servera (localhost - zadaj 'l'): ")
        if serverIp == "l" or validator.validIp(serverIp):
            break
        else:
            print("ZLy vstup alebo format ip, skus znova\n")

    while True:
        port = input("Zadaj port (nepovinne): ")
        if port == "" or validator.validPort(port):
            break
        else:
            print("Port musi byt v rozmedzi 0 - 65535 vratane, skus znova\n")

    while True:
        packetSize = input("Zadaj maximalnu velkost paketu (" + str(g.HEADER_SIZE) + " - " + str(g.MAX_PACKET_SIZE) + "): ")
        if validator.validPacketSize(packetSize):
            break
        else:
            print("ZLa velkost, skus znova\n")

    while True:
        err = input("Chces posielat aj chybove pakety? (y/n): ")
        if err == "y" or err == "n":
            break
        else:
            print("ZLy vstup, skus znova\n")

    print("\n")

    # innitializing client
    client = Client(serverIp, port, int(packetSize), err)

def serverStart():
    # declare variables
    ip, port = None, None

    # reading values
    while True:
        ip = input("\nChces komunikovat cez localhost(l) alebo s inym pc(p): ")
        if ip == "l" or ip == "p":
            break
        else:
            print("ZLy vstup, skus znova\n")

    while True:
        port = input("Zadaj port (nepovinne): ")
        if port == "" or validator.validPort(port):
            break
        else:
            print("Port musi byt v rozmedzi 0 - 65535 vratane, skus znova\n")

    print("\n")

    # innitializing client
    server = Server(ip, port)


if __name__ == "__main__":
    main()
