import logging

# sizes
MAX_PACKET_SIZE = 1500  # with an UDP header, my header and ip header
HEADER_SIZE = 9
# MAX_RAW_DATA_SIZE =  # bytes for a raw data (without headers)
PACKETS_PACK_SIZE = 20
MAX_PORT_NUM = 65535

# formats
HEADER_FORMAT = '=Ibi'   # I - for a packet order, B - for a flag, i - crcvalue


# source: https://gist.github.com/oysstu/68072c44c02879a2abf94ef350d1c7c6
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


logging.basicConfig(filename="logs.log", format='%(asctime)s %(message)s', filemode='w')
logger = logging.getLogger() 
logger.setLevel(logging.DEBUG) 
