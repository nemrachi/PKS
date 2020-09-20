import globalFile as g

def validIp(self, ip: str) -> bool:
    splitIp = ip.split(".")
    if len(splitIp) == 4:
        for x in splitIp:
            if not (0 <= int(x) <= 250):
                return False
        return True
    else:
        return False

def validPort(self, port: str) -> bool:
    if (0 <= int(port) <= g.MAX_PORT_NUM):
        return True
    else:
        return False

def validPacketSize(self, packetSize: str) -> bool:
    if packetSize == "":
        return False
    if (g.HEADER_SIZE <= int(packetSize) <= g.MAX_PACKET_SIZE):
        return True
    else:
        return False

def validateFlag(self, wantedFlag: str, recievedFlag: str) -> bool:
    return True if ((wantedFlag[0] == recievedFlag[0]) and (wantedFlag[1] == recievedFlag[1])) else False
