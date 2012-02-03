import tornado.iostream
import tornado.ioloop
from tornado import gen
import urlparse
import logging
import socket
from Crypto.Util.number import long_to_bytes
import tornado.options
import json
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
def make_request(request, callback=None):
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
    data = json.loads(body)
    callback( Response(code, headers, data) )
    
@gen.engine
def login(username, password, callback=None):
    request = Request('GET', '%s/api/login/?new=1&user=%s' % (options.srp_root, username))
    response = yield gen.Task( make_request, request )
    if response.error:
        logging.error('response error')
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
        logging.error('need to pad..')
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

    client_data = { 'key': aeskey }
    client_data.update( response.body )
    callback(client_data)
    ioloop.stop()


@gen.engine
def go():
    result = yield gen.Task( login, 'kylepoo9', 'pass' )
    logging.info('login with result %s' % result)


ioloop = tornado.ioloop.IOLoop.instance()
go()
ioloop.start()
