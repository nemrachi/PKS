import os
import socket
import re
# s = input()
# splitted = s.split('\\')
# print(splitted)
#
# inputFile = open(s, 'r+b')
# # inputFile = inputFile.read()
#
# print(os.path.getsize(s))
#


ip = "127.0.0.1"
print(re.findall("[0-9]", ip))
listRE = re.findall("[0-9]", ip)
print(len(listRE))
