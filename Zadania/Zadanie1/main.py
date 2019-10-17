import socket
import struct
import sys
import threading
import sender
import receiver


while True:
    userInput = input("Choose wisely: (h - help)\n")

    if userInput == "0":
        print("You choose to be sender")
        message = input("Type message, you want to send:\n")
        sender.send(message)
    elif userInput == "1":
        print("You choose to be receiver")
        receiver.receive()
    elif userInput == "h":
        print("Help:\n\t0 - sender\n\t1 - receiver\n\th - print this text\n\te - print this text")
    elif userInput == "e":
        print("ending program")
        break
