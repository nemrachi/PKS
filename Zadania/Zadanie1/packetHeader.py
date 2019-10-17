import struct

formatHeader = 'i B'
packetHeader = struct.pack(formatHeader, None, None)


def set_header(packetOrder, flag):
    global packetHeader
    packetHeader = struct.pack(formatHeader, packetOrder, flag)
    return packetHeader


def get_header():
    return packetHeader
