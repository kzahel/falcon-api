import tornado.iostream
import tornado.ioloop
from tornado import gen
import urlparse
import logging
import socket
from Crypto.Util.number import long_to_bytes
import tornado.options
import json
import bitarray
import urllib
import time
from hashlib import sha1
from tornado.escape import utf8
from tornado.util import b
from tornado.httputil import HTTPHeaders
from tornado.escape import native_str
import re
from tornado.options import define, options
define('srp_root',default='http://192.168.56.1:9090')
#define('srp_root',default='https://remote-staging.utorrent.com')
define('debug',default=True)
tornado.options.parse_command_line()
if options.debug:
    import pdb
import random
def random_hex(length):
    chars = map(str,range(10)) + list('abcdef')
    return ''.join([random.choice(chars) for _ in range(length)])

def parse_headers(data):
    data = native_str(data.decode("latin1"))
    first_line, _, header_data = data.partition("\n")
    match = re.match("HTTP/1.[01] ([0-9]+)", first_line)
    assert match
    code = int(match.group(1))
    headers = HTTPHeaders.parse(header_data)
    return code, headers

def on_close():
    logging.error('stream close')

from tornado.escape import _unicode

class Response(object):
    def __init__(self, code, headers, body):
        self.code = code
        self.headers = headers
        self.body = body
        self.error = True if code >= 400 else False

class Request(object):
    def __init__(self, method, url, headers=None):
        self.method = method
        self.url = url
        self.url_parsed = urlparse.urlsplit(url)
        secure = True if self.url_parsed.scheme == 'https' else False
        if self.url_parsed.netloc.find(':') != -1:
            host, port = self.url_parsed.netloc.split(':')
            port = int(port)
        else:
            host = self.url_parsed.netloc
            port = 443 if secure else 80

        self._conn_host = host
        self._conn_port = port
        self._conn_secure = secure

        self.headers = headers or {}

    def make_request_headers(self):
        if self.url_parsed.query:
            uri = '%s?%s' % (self.url_parsed.path, self.url_parsed.query)
        else:
            uri = self.url_parsed.path
        request_lines = [utf8("%s %s HTTP/1.1" % (self.method,
                                                  uri))]
        #logging.info('writing headers %s' % request_lines)
        if 'Host' not in self.headers:
            self.headers["Host"] = self.url_parsed.netloc
        for k, v in self.headers.items():
            line = utf8(k) + b(": ") + utf8(v)
            request_lines.append(line)
        toreturn = b("\r\n").join(request_lines) + b("\r\n\r\n")
        return toreturn

@gen.engine
def make_request(request, expectjson=True, cipher=None, callback=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    stream = tornado.iostream.SSLIOStream(s) if request._conn_secure else tornado.iostream.IOStream(s)
    stream._always_callback = True
    addr = (request._conn_host, request._conn_port)
    #logging.info('connect to %s' % str(addr))
    yield gen.Task( stream.connect, addr )
    if stream.error:
        logging.error('could not go :-(')
        raise StopIteration
    yield gen.Task( stream.write, request.make_request_headers() )
    if stream.error:
        logging.error('could not go :-(')
        raise StopIteration
    rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )
    code, headers = parse_headers(rawheaders)
    #logging.info('code %s, headers %s' % (code,headers))
    body = yield gen.Task( stream.read_bytes, int(headers['Content-Length']) )
    stream.close()
    if not body:
        logging.error('conn closed reading for body?')
        raise StopIteration
    #logging.info('got body %s' % body)
    if cipher:
        cipher.ivoffset = int(headers['X-Bt-Seq'])
        encbody = body
        body = cipher.encrypt(cipher.hex_to_ascii(body))

    if expectjson:
        data = json.loads(body)
    else:
        data = body
    callback( Response(code, headers, data) )
    
@gen.engine
def login(username, password, callback=None):
    request = Request('GET', '%s/api/login/?new=1&user=%s' % (options.srp_root, username))
    response = yield gen.Task( make_request, request )
    if response.error:
        logging.error('response error')
        raise StopIteration

    if 'guid' not in response.body:
        logging.error('response %s' % response.body)
        raise StopIteration
        
    session = response.body['guid']
    modulus, generator, salt = map(int,response.body['response'])

    exponent = int(random_hex(40), 16)
    public_key = pow(generator, exponent, modulus)
    #logging.info('pub key %s' % public_key)
    args = { 'username': username,
             'pub': str(public_key),
             'time': int(time.time() * 1000),
             'GUID': session }
    request = Request('GET', '%s/api/login/?%s' % (options.srp_root,urllib.urlencode(args)))
    response = yield gen.Task( make_request, request )
    if response.error:
        logging.error('response error')
        raise StopIteration

    client_public_key = int(response.body['response'][0])
    
    if client_public_key % modulus == 0:
        logging.error('got invalid public key')
        raise StopIteration

    kay = 3
    u = int(sha1(long_to_bytes(public_key) + long_to_bytes(client_public_key)).hexdigest(), 16)

    if u % modulus == 0:
        logging.error('invalid exponent...')
        raise StopIteration

    userpassint = int(sha1( '%s:%s' % (username,password) ).hexdigest(),16)
    passint = int( sha1( long_to_bytes(salt) + long_to_bytes( userpassint ) ).hexdigest(), 16 )

    gtox = pow(generator, passint, modulus)

    neg_gtox_kay = (modulus - gtox) * kay

    key_base = (client_public_key + neg_gtox_kay) % modulus

    key_exponent = exponent + (u * passint)
    client_num = pow( key_base, key_exponent, modulus )
    client_hash = sha1( long_to_bytes(client_num) ).hexdigest()
    client_key = int(client_hash, 16)
    
    aeskey = hex(client_key)[2:-1] # remove 0x and L
    if len(aeskey) < 40:
        aeskey = '0' + aeskey
    if len(aeskey) > 40:
        aeskey = aeskey[:40]

    def compute_verify_client_key():
        xor_term = int(sha1(long_to_bytes(modulus)).hexdigest(),16) ^ int(sha1(long_to_bytes(generator)).hexdigest(),16)
        A = public_key
        B = client_public_key
        M1_pre_hash = ''.join( [ long_to_bytes(xor_term),
                                 long_to_bytes( int(sha1(username).hexdigest(),16) ),
                                 long_to_bytes( salt ),
                                 long_to_bytes( A ),
                                 long_to_bytes( B ),
                                 long_to_bytes( client_key ) ] )
        M1 = int(sha1(M1_pre_hash).hexdigest(),16)
        return M1

    M1 = compute_verify_client_key()
    
    args = { 'username': username,
             'verify': M1,
             'time': int(time.time() * 1000),
             'GUID': session }
    request = Request('GET', '%s/api/login/?%s' % (options.srp_root,urllib.urlencode(args)))
    response = yield gen.Task( make_request, request )
    if response.error:
        logging.error('got verify response error')
        raise StopIteration
    if 'error' in response.body:
        logging.error( response.body )
        raise StopIteration

    def compute_verify_M2():
        A = public_key
        M2 = sha1( ''.join( [ long_to_bytes(A),
                              long_to_bytes(M1),
                              long_to_bytes(client_key) ] ) ).hexdigest()
        return int(M2, 16)

    M2 = int(response.body['response'][0])
    del response.body['response']
    if M2 != compute_verify_M2():
        logging.error('client password mismatch')
        raise StopIteration

    client_data = { 'key': aeskey,
                    'guid': session
                    }
    client_data.update( response.body )
    callback(client_data)

def loglshift(val, n):
    # logical left shift
    shifted = val << n
    if (1<<31) & shifted:
        return shifted - (1<<32)
    else:
        return shifted

assert loglshift(255,16) == 16711680
assert loglshift(234,24) == -369098752

def hexToBytes(hex):
    return [ int( hex[i*2]+hex[i*2+1],16 ) for i in range(len(hex)/2) ]
def bytesToHex(bytes):
    return ''.join( pad(hex(byte)[2:],2,'0') for byte in bytes )
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
import struct

    

#assert bytesToWords([239, 88, 250, 18]) == [-279381486]

#assert bytesToWords([239, 88, 250, 18, 180, 39, 224, 127, 10, 94, 200, 21, 181, 9, 237, 254, 205, 207, 103, 15]) == [-279381486, -1272455041, 173983765, -1257640450, -842045681]
assert bytesToWords([198, 218, 79, 150, 40, 6, 187, 93, 115, 41, 205, 156, 100, 156, 161, 23, 199, 14, 29, 3]) == [-958771306, 671529821, 1932119452, 1687986455, -955376381]


#def rshift(val, n): return val>>n if val >= 0 else (val+0x100000000)>>n
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

def pad(s,width,padwith):
    if len(s) < width:
        return (padwith * (width-len(s))) + s
    elif len(s) > width:
        raise Exception('cant pad..too wide')
    else:
        return s

import math

class Cipher:
    def __init__(self, key):
        self.ivoffset = 0
        self.block_size = 16
        bytes = hexToBytes(key)
        words = bytesToWords(bytes)
        key_words = words[:4]
        self.iv = wordsToBytes( [words[-1],words[-1],words[-1],words[-1]] )
        #self.cipher = AES.new( self.hex_to_ascii(key[:32]), AES.MODE_CTR, counter=self.counter )
        self.block_size = 16
        self.cipher = AES.new( self.hex_to_ascii(key[:32]), AES.MODE_ECB )

    def hex_to_ascii(self, data):
        if len(data)%2 != 0:
            pdb.set_trace()
        chars = []
        for i in range(len(data)/2):
            chars.append( chr( int(data[i*2:i*2+2], 16) ) )
        return ''.join(chars)

    def encrypt(self, data):
        return self.decrypt_manual(data)

    def decrypt_manual(self, data):
        #return self.decrypt(data)
        # do chunk at a time, manually doing ctr mode...
        cur_block = 0
        output = []
        while cur_block < int(math.ceil(len(data)/float(self.block_size))):
            output.append( self.decrypt_block( data[cur_block*self.block_size : (cur_block+1)*self.block_size] ) )
            cur_block += 1

        return ''.join(output)

    def decrypt_block(self, input):
        ctr = self.counter()
        mask = self.cipher.encrypt(ctr)
        endian = 'big'

        if len(input) < self.block_size: # pad with zeroes
            inputp = input + ('\x00'*(self.block_size-len(input)))
        else:
            inputp = input

        a = bitarray.bitarray(endian=endian)
        a.frombytes(mask)

        b = bitarray.bitarray(endian=endian)
        b.frombytes(inputp)
        print 'xor',self.ivoffset
        print 'iv',self.iv
        print 'inp',map(ord,input)
        print 'mas',map(ord,mask)
        output = a ^ b
        if len(input) < self.block_size:
            toreturn = output.tobytes()[:len(input)]
        else:
            toreturn = output.tobytes()

        print 'ret',map(ord, toreturn)
        return toreturn

    def decrypt(self, data):
        logging.info('cipher: decrypt %s' % [data])

        chars = []
        for i in range(len(data)/2):
            chars.append( chr( int(data[i*2:i*2+2], 16) ) )
        data = ''.join(chars)
        logging.info('cipher: toascii %s' % [data])

        decrypted = self.cipher.decrypt(data)
        logging.info('cipher: decrypted to %s' % [decrypted])
        return decrypted

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
        #logging.info('called ctr, returning %s' % map(ord,toreturn))
        return toreturn

from Crypto.Cipher import AES
@gen.engine
def go():
    username = 'kylepoo8'
    password = 'pass'

    result = yield gen.Task( login, username, password )
    logging.info('login with result %s' % result)

    args = { 'GUID': result['guid'],
             'bt_talon_tkt': result['bt_talon_tkt'] }
    url = '%s/client/gui/token.html?%s' % (result['host'], urllib.urlencode(args))

    request = Request('GET', url)
    cipher = Cipher(result['key'])

    print '\nvar client_data=',json.dumps( { 'key': result['key'],
                             'bt_talon_tkt': result['bt_talon_tkt'],
                             'bt_user': username,
                             'host': options.srp_root,
                             'guid': result['guid'] } ),'\n'

    response = yield gen.Task( make_request, request, expectjson=False, cipher=cipher )
    #logging.info('token response %s' % [response.body])


@gen.engine
def test_decrypt():
    client_data= {"guid": "OGMwd0hduPh8u06OMRXe", "host": "http://192.168.56.1:9090", "bt_talon_tkt": "9XJP8oFnvFQ2GGPtHM8Z8VRuJJVDULhkiOJxbmPmOG9nAMfh4IT2KPCuC0n0Nj0P", "key": "7553742f0fdcf3b72fb56edbc92033c6290fc69e", "bt_user": "kylepoo8"}

    args = { 'GUID': client_data['guid'],
             'bt_talon_tkt': client_data['bt_talon_tkt'] }
    cipher = Cipher(client_data['key'])

    #text = 'aoeuathouenthaouoauea ouenthoa ntuehoantehuntoahueoantuehnteoahuhnoahentuhanohu'
    #encrypted = cipher.encrypt(text)
    #pdb.set_trace()

    url = '%s/client/gui/token.html?%s' % (client_data['host'], urllib.urlencode(args))
    request = Request('GET', url)
    response = yield gen.Task( make_request, request, expectjson=False, cipher=cipher )
    logging.info('token response %s' % [response.body])


if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    #go()
    test_decrypt()
    ioloop.start()
