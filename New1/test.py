# Online Python compiler (interpreter) to run Python online.
# Write Python 3 code in this online editor and run it.
import sys

def flagToChar(flag: str):
    return chr(int((flag).encode(), 2))

def charToFlag(char):
    return str(bin(ord(char)))[2:]


x = '11110010'

print(charToFlag('ò'))
print(flagToChar(x))
