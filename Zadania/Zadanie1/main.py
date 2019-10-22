import socket
import struct
import sys
import threading
from sender import Sender
from receiver import Receiver
import receiver


while True:
    userInput = input("Choose wisely:\n(h - help)\n")

    # --------------------------------------------------
    # Sender
    # --------------------------------------------------
    if userInput == "0":
        print("You choose to be sender")
        while True:
            packetSize = input("Choose packet size (max 1487B): ")  # -13 -> 8 UDP header, 5 my header
            if packetSize is '':
                sender = Sender()
                break
            elif int(packetSize) > 1487:
                print("Wrong input")
                continue
            else:
                sender = Sender("127.0.0.1", int(packetSize))
            break

    # --------------------------------------------------
    # Receiver
    # --------------------------------------------------
    elif userInput == "1":
        print("You choose to be receiver")
        receiver = Receiver()

    # --------------------------------------------------
    # Help
    # --------------------------------------------------
    elif userInput == "h":
        print("Help:\n\t0 - sender\n\t1 - receiver\n\th - print this text\n\te - exit")
    # --------------------------------------------------
    # Exit
    # --------------------------------------------------
    elif userInput == "e":
        print("ending program")
        break
