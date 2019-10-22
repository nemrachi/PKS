import flags
import struct
import binascii
import flags as flag

# intFlag = int((flag.SYN + flag.CRC_KEY).encode(), 2)
# "{0:b}".format(intFlag)
# print(bin(intFlag) == bin(17))
# print(str(bin(intFlag)))
# print("{0:08b}".format(intFlag))
# strFlag = "{0:08b}".format(intFlag)
# print(strFlag[:4])
# print(strFlag[4:])

shortStr = "Hello fucking world"

shortStr = shortStr.encode()   # Or other appropriate encoding
structSTR = struct.pack("=IB", 1, 17) + shortStr[:1500]

# receive
(header), data = struct.unpack("=IB", structSTR[:5]), structSTR[5:]

print(header)
print(data)
