import analyzer as a
import os
from scapy.all import *
import ntpath


# opens a pcap file and returns data
def getDataFromPcap():
    count = 0
    while True:
        fileName = input("> Enter a path to the pcap file (e - exit): ")
        # fileName = "C:\\Users\\emari\\projects\\PKS\\Zadania\\New_Zadanie1\\vzorky_pcap_na_analyzu\\trace-26.pcap"

        # checks if the entered file path leads to an existing file
        if os.path.isfile(fileName):
            print("> File " + os.path.basename(fileName) + " is opening.\n")
            dump = rdpcap(fileName) # reads the pcap file
            return dump, ntpath.basename(fileName).split(".")[0]

        else:
            if (fileName == "e"):
                exit(True)
            print(">>> Can't open the file or the file doesn't exists.\n")
            count += 1
            if (count == 5):
                exit(True)


# main function
def main():
    nextFile = True

    while nextFile:
        dump, traceName = getDataFromPcap()

        outChoice = input("> Write output to a text file ('f') or to the console (other)?: ")
        # outChoice = ""

        # start analyzing
        analyzer = a.Analyzer(dump, traceName, outChoice)
        analyzer.firstPoint()

        nfInput = input("> Open a new file? (y/n): ")
        nextFile = True if (nfInput == 'y') else False


if __name__ == "__main__":
    try:
        main()
    except Scapy_Exception as scapyE:
        print("\t>>> Error: " + str(scapyE) + "\n")
        main()
