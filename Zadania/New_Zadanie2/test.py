# Online Python compiler (interpreter) to run Python online.
# Write Python 3 code in this online editor and run it.
import sys
import socket
import struct
import flags as flag

# =Ibi
def flagToChar(flag: str) -> int:
        print(int(flag))
        return int(flag)

def charToFlag(self, char: int):
        return str(char)

print(type(flagToChar(flag.SYN + flag.METADATA)))
packet = struct.pack("=B", flagToChar(flag.SYN + flag.METADATA))
