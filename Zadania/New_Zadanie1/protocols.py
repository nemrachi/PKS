import os

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
                protocols[sl[0]] = sl[1].rstrip()

    else:
        print(">>> Can't open the file or the file doesn't exists.\n")
        exit(True)

    return protocols
