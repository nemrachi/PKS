SYN = "1" # first connection establishment or 3-way handshake
ACK = "2"
DATA = "3"
METADATA = "4"
FIN = "5" # connection termination
ERR = "6"
 
# second 4b
NONE = "0"
STRING = "1"
TXT_FILE = "2"
IMG_FILE = "3"
SOUND_FILE = "4"
VIDEO_FILE = "5"
EXE_FILE = "6"
KEEP_ALIVE = "7"
CORRUPTED = "8"

# crc kluc pripajam na koniec kazdeho packetu a v receivervi si pomocou algo vypicitam z toho klucu spravnu 
# bytearray - zakodovat to do byte arraye