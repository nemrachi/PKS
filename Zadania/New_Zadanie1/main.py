import analyser as a
import os
from scapy.all import *
import ntpath


# opens a pcap file and returns data and file's name
def getDataFromPcap() -> Tuple[PacketList, str]:
    while True:
        fileName = input("> Enter a path to the pcap file (e - exit): ")

        # checks if the entered file path leads to an existing file
        if os.path.isfile(fileName):
            print("> File " + os.path.basename(fileName) + " is opening.\n")
            dump = rdpcap(fileName) # reads the pcap file
            fileName = ntpath.basename(fileName).split(".")[0]

            return dump, fileName

        else:
            if (fileName == "e"):
                exit(True)
            print(">>> Can't open the file or the file doesn't exists.\n")


# main function
def main():
    nextFile = True

    # loop for inserting files continually
    while nextFile:
        dump, traceName = getDataFromPcap()

        filteredProtocol = input("> Filtered protocol: ")
        print("")

        outChoice = input("> Write output to a text file (f) or to the console (other)?: ")
        print("")

        # start analysing
        analyser = a.Analyser(dump, traceName, filteredProtocol, outChoice)
        analyser.analyse()
        print("> Analysis is done.\n")

        nfInput = input("> Open a new file? (y/n): ")
        nextFile = True if (nfInput == 'y') else False


if __name__ == "__main__":
    main()
