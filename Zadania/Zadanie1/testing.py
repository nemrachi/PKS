import flags

strFlag = int((flags.SYN + flags.CRC_KEY).encode(), 2)
strFlag = "{0:08b}".format(strFlag)
print(strFlag)

strFlag = ''.join((strFlag[:0], flags.FIN_DATA, strFlag[4:]))

print(strFlag)
print(int(strFlag.encode(), 2))
