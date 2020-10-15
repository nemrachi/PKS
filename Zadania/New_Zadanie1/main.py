import analyzer as a
import os
from socket import fromshare
import struct
from scapy.all import *


# opens a pcap file and returns data
def getDataFromPcap():
    while True:
        # fileName = input("> Enter a path to the pcap file (e - exit): ")
        fileName = "C:\\Users\\emari\\projects\\PKS\\Zadania\\New_Zadanie1\\vzorky_pcap_na_analyzu\\trace-2.pcap"

        # checks if the entered file path leads to an existing file
        if os.path.isfile(fileName):
            print("> File " + os.path.basename(fileName) + " is opening.\n")
            dump = rdpcap(fileName) # reads the pcap file
            return dump

        else:
            if (fileName == "e"):
                exit(True)
            print(">>> Can't open the file or the file doesn't exists.\n")


# main function
def main():
    nextFile = True

    while nextFile:
        dump = getDataFromPcap()

        # outChoice = input("> Write output to a text file ('f') or to the console (other)?: ")
        outChoice = ""

        analyzer = a.Analyzer(dump, outChoice)
        analyzer.firstPoint()

        nf = input("Open a new file? (y/n): ")
        nextFile = True if (nf == 'y') else False


if __name__ == "__main__":
    try:
        main()
    except Scapy_Exception as scapyE:
        print("\t>>> Error: " + str(scapyE) + "\n")
        main()
