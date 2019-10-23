import socket
import struct
import sys
import threading
import re
from sender import Sender
from receiver import Receiver
import receiver

try:
    while True:
        print("Choose wisely:")
        print("\t0 - sender\n\t1 - receiver\n\te - exit")
        userInput = input()

        # --------------------------------------------------
        # Sender
        # --------------------------------------------------
        if userInput == "0":
            print("Role: sender")

            while True:
                ipAddress = input("Enter IP: ")
                if ipAddress is '':
                    break
                else:
                    if ipAddress.count('.') == 3 and len(re.findall("[0-9]", ipAddress)) > 4:
                        print("Valid IP address")
                        break
                    else:
                        print("Invalid IP address")
                        continue

            while True:
                port = input("Enter port: ")
                if port is '':
                    break
                else:
                    if 0 <= int(port) <= 65535:
                        print("Valid port number")
                        break
                    else:
                        print("Invalid port number")
                        continue

            while True:
                packetSize = input("Enter packet size (max 1487B): ")
                # (max ethernet) 1500 - 13 -> 8 UDP header, 5 my header
                if packetSize is '':
                    print("Please, enter something")
                    continue
                elif int(packetSize) > 1487:
                    print("Please, enter smaller size")
                    continue
                else:
                    break

            sender = Sender(ipAddress, port, int(packetSize))

        # --------------------------------------------------
        # Receiver
        # --------------------------------------------------
        elif userInput == "1":
            print("Role: receiver")

            while True:
                port = input("Enter port: ")
                if port is '':
                    break
                else:
                    if 0 <= int(port) <= 65535:
                        print("Valid port number")
                        break
                    else:
                        print("Invalid port number")
                        continue

            receiver = Receiver(port)
        # --------------------------------------------------
        # Exit
        # --------------------------------------------------
        elif userInput == "e":
            print("Ending program...")
            break
        else:
            print("Wrong input")

except Exception as e:
    print("--------------------------------------------------")
    print("error:", e)
    print("--------------------------------------------------")
