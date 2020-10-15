import os


# get frame types and protocols from txt file and save them in dictionary
def getProtocols() -> dict:
    protocols = {}

    filePath = os.path.dirname(__file__) + "\protocols.txt"

    if os.path.isfile(filePath):
        file = open(filePath, 'r')
        lines = file.readlines()
        file.close()

        for l in lines:
            if (l[0] != "#"):
                sl = l.split(" ", 1)
                protocols[sl[0]] = sl[1].rstrip() # key is hex number of frame/protocol

    else:
        print(">>> Can't open the file or the file doesn't exists.\n")
        exit(True)

    return protocols
