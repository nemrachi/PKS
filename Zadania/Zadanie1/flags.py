# first 4b
SYN = '0001'
ACK = '0010'
METADATA = '0100'
DATA = '1000'
SYN_DATA = '1001'  # first data packet
FIN_DATA = '1100'  # last data packet
ERR = '0000'

# second 4b

NONE = '0000'
CRC_KEY = '0001'
STRING = '0010'
TXT_FILE = '0011'
IMG_FILE = '0100'
SOUND_FILE = '0101'
VIDEO_FILE = '0110'
EXE_FILE = '0111'

MISSING_PACKET = '1000'
