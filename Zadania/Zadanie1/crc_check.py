# def xor(a, b):
#     # initialize result
#     result = []
#
#     # Traverse all bits, if bits are
#     # same, then XOR is 0, else 1
#     for i in range(1, len(b)):
#         if a[i] == b[i]:
#             result.append('0')
#         else:
#             result.append('1')
#
#     return ''.join(result)
#
#
# # Performs Modulo-2 division
# def mod2div(divident, divisor):
#     # Number of bits to be XORed at a time.
#     pick = len(divisor)
#
#     # Slicing the divident to appropriate
#     # length for particular step
#     tmp = divident[0: pick]
#
#     while pick < len(divident):
#
#         if tmp[0] == '1':
#
#             # replace the divident by the result
#             # of XOR and pull 1 bit down
#             tmp = xor(divisor, tmp) + divident[pick]
#
#         else:  # If leftmost bit is '0'
#
#             # If the leftmost bit of the dividend (or the
#             # part used in each step) is 0, the step cannot
#             # use the regular divisor; we need to use an
#             # all-0s divisor.
#             tmp = xor('0' * pick, tmp) + divident[pick]
#
#             # increment pick to move further
#         pick += 1
#
#     # For the last n bits, we have to carry it out
#     # normally as increased value of pick will cause
#     # Index Out of Bounds.
#     if tmp[0] == '1':
#         tmp = xor(divisor, tmp)
#     else:
#         tmp = xor('0' * pick, tmp)
#
#     checkword = tmp
#     return checkword
#
#
# def data_with_remainder(strData, CRCpolynomial):
#     strBin = (''.join(format(ord(x), 'b') for x in strData))
#     print('data:', strBin)
#
#     l_key = len(CRCpolynomial)
#
#     # Appends n-1 zeroes at end of data
#     appended_data = strBin + '0' * (l_key - 1)
#     remainder = mod2div(appended_data, CRCpolynomial)
#
#     # Append remainder in the original data
#     codeword = strBin + remainder
#     return codeword
#
#
# def decodeData(data, key):
#     l_key = len(key)
#
#     # Appends n-1 zeroes at end of data
#     #appended_data = data + '0' * (l_key - 1)
#     print('in decodeData:\n     ', data)
#     remainder = mod2div(data, key)
#
#     return remainder
#
# contents = input("Enter data you want to send->")
# # fileF = open("C:\\Users\\emari\\Pictures\\kirb.jpg", "r+b")
# # contents = fileF.read()
# # print(contents)
#
# key = "1001"
#
# ans = data_with_remainder(str(contents), key)
# ans = (len(contents)*8 - (len(ans) - (len(key)-1))) * "0" + ans
# print('ans: ', ans)
# data = []
# for i in range(0, (len(ans)//8)+1):
#     print(ans[i*8:(i+1)*8])
#     data.append(ans[i*8:(i+1)*8])
# encoded = bytearray()
# for i in data:
#     i = int(i, 2)
#     encoded.append(i)
#
# for elem in encoded:
#     print(chr(elem))
#
# ans1 = decodeData(str(encoded), key)
# print(ans1)


def crc16(data: bytes, poly=0x8408):
    '''
    CRC-16-CCITT Algorithm
    '''
    data = bytearray(data)
    crc = 0xFFFF
    for b in data:
        cur_byte = 0xFF & b
        for _ in range(0, 8):
            if (crc & 0x0001) ^ (cur_byte & 0x0001):
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            cur_byte >>= 1
    crc = (~crc & 0xFFFF)
    crc = (crc << 8) | ((crc >> 8) & 0xFF)

    return crc & 0xFFFF


print(type(crc16('hello'.encode(), 0x8408)))
hexa = hex(crc16('hello'.encode(), 0x8408))
strVol = bytearray.fromhex(hexa).decode()

print(strVol)
