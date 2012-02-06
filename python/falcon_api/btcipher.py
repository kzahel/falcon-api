from Crypto.Cipher import AES
import struct

from util import pad

def loglshift(val, n):
    # logical left shift
    shifted = val << n
    if (1<<31) & shifted:
        return shifted - (1<<32)
    else:
        return shifted

assert loglshift(255,16) == 16711680
assert loglshift(234,24) == -369098752

def rshift(val, n): return (val % 0x100000000) >> n # faster
def wordsToBytes(words):
    bitmask = 1
    for i in range(7): bitmask = (bitmask << 1) | 1
    bytes = []
    for i in range(len(words)):
        bstart = i*4
        for j in range(4):
            #bytes[bstart+j] = (words[i] & (bitmask << (8*(3-j)))) >>> (8*(3-j))
            #bytes.append( (words[i] & (bitmask << (8*(3-j)))) >> (8*(3-j)) ) #XXX >>> does not exist
            rval = loglshift(bitmask, (8*(3-j)))

            val = words[i] & rval
            bytes.append( rshift( val, 8*(3-j) ) )
    return bytes

assert wordsToBytes([-955376381]) == [199, 14, 29, 3]


def hexToBytes(hex):
    return [ int( hex[i*2]+hex[i*2+1],16 ) for i in range(len(hex)/2) ]

def bytesToWords(bytes):
    # probably not working as indended
    if len(bytes) % 4 != 0:
        logging.error('need to pad')
        pdb.set_trace()
    numwords = len(bytes) / 4

    words = [ bytes[(j<<2)+3] |
              bytes[(j<<2)+2] << 8 |
              bytes[(j<<2)+1] << 16 |
              loglshift( bytes[(j<<2)], 24) for j in range(numwords) ]
    return words


assert bytesToWords([239, 88, 250, 18]) == [-279381486]
assert bytesToWords([239, 88, 250, 18, 180, 39, 224, 127, 10, 94, 200, 21, 181, 9, 237, 254, 205, 207, 103, 15]) == [-279381486, -1272455041, 173983765, -1257640450, -842045681]
assert bytesToWords([198, 218, 79, 150, 40, 6, 187, 93, 115, 41, 205, 156, 100, 156, 161, 23, 199, 14, 29, 3]) == [-958771306, 671529821, 1932119452, 1687986455, -955376381]


class Cipher:
    def __init__(self, key):
        self.ivoffset = 0
        self.block_size = 16
        bytes = hexToBytes(key)
        words = bytesToWords(bytes)
        key_words = words[:4]
        self.iv = wordsToBytes( [words[-1],words[-1],words[-1],words[-1]] )
        self.cipher = AES.new( self.hex_to_ascii(key[:32]), AES.MODE_CTR, counter=self.counter )
        self.block_size = 16
        #self.cipher = AES.new( self.hex_to_ascii(key[:32]), AES.MODE_ECB )

    def remove_trailing_nulls(self, data):
        i = len(data) - 1
        while data[i] == '\x00':
            i -= 1
        return data[:i+1]

    def hex_to_ascii(self, data):
        if len(data)%2 != 0:
            pdb.set_trace()
        chars = []
        for i in range(len(data)/2):
            chars.append( chr( int(data[i*2:i*2+2], 16) ) )
        return ''.join(chars)

    def encrypt(self, data):
        return self.cipher.decrypt(data)

    def encrypt_pad(self, data):
        padto = self.block_size * 4
        toreturn = self.encrypt(data)
        if len(data) % padto != 0:
            self.encrypt( '\x00' * (padto - (len(data)%padto)) )
        return toreturn

    def counter(self):
        ctr = self.iv[:]

        offsetstr = hex(self.ivoffset)[2:]
        if len(offsetstr) > 8:
            # if ivoffset gets VERY large, need to pad to ... 16, 24
            raise Exception('ivoffset to large... need to fix')
        offset = pad(offsetstr, 8, '0')

        l = len(offset)

        i=0
        offsets = []
        while i<l:
            offsets.append( int( offset[i] + offset[i + 1], 16 ) )
            i+=2
        offsets.reverse()
        l = len(offsets)

        carryover = 0
        i=0
        while i<l:
            offsets[i] += carryover
            ctr[i] += offsets[i]
            carryover = 1 if ctr[i] >= 256 else 0
            ctr[i] %= 256
            i += 1
        
        self.ivoffset += 1
        toreturn = ''.join(map(chr, ctr))
        return toreturn

