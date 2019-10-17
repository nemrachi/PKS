import flags

print(flags.SYN+flags.CRC_KEY)
print(len(flags.SYN+flags.CRC_KEY))
num = int(flags.SYN+flags.CRC_KEY, 2)
print(num)
binNum = bin(num)
print(binNum)
