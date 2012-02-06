#!/usr/bin/env python

# messy first-run at falcon SRP key negotiation and aes ctr decryption


import tornado.iostream
import tornado.ioloop
from tornado import gen
import urlparse
import logging
import socket
import sys
import tornado.options
import json
import bitarray
import urllib
import random
import time
from hashlib import sha1
from tornado.escape import utf8
from tornado.util import b
from tornado.httputil import HTTPHeaders
from tornado.escape import native_str
import re
from tornado.options import define, options
from btcipher import Cipher
import srp
from util import pad, parse_token

define('srp_root',default='http://192.168.56.1:9090')
#define('srp_root',default='https://remote-staging.utorrent.com')
define('debug',default=True)
tornado.options.parse_command_line()
if options.debug:
    import pdb

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
    def __init__(self, method, url, headers=None, body=None):
        self.method = method
        self.url = url
        self.body = body
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

    def make_request_str(self):
        if self.body:
            return self.make_request_headers() + self.body
        else:
            return self.make_request_headers()

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
    yield gen.Task( stream.write, request.make_request_str() )
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
        if 'X-Bt-Seq' not in headers:
            logging.error('no encryption sequence in response %s, %s' % (code, headers))
            raise StopIteration
            
        cipher.ivoffset = int(headers['X-Bt-Seq'])
        logging.info('got headers %s' % headers)
        #logging.info('got ivoffset %s' % headers['X-Bt-Seq'])
        encbody = body

        body = cipher.encrypt(cipher.hex_to_ascii(body))

    if expectjson:
        data = json.loads(body)
    else:
        data = body
    callback( Response(code, headers, data) )
    
@gen.engine
def login(username, password, callback=None):
    args = {'user': username}
    request = Request('GET', '%s/api/login/?%s' % (options.srp_root, urllib.urlencode(args)))
    response = yield gen.Task( make_request, request )
    if response.error:
        logging.error('response error')
        raise StopIteration

    if 'guid' not in response.body:
        logging.error('response %s' % response.body)
        raise StopIteration
        
    session = response.body['guid']
    modulus, generator, salt = map(int,response.body['response'])

    exponent, public_key = srp.create_public_key(modulus, generator, salt)

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

    aeskey, client_key, M1 = srp.verify_client_key(username, password, modulus, generator, salt, exponent, public_key, client_public_key)
    
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

    M2 = int(response.body['response'][0])
    del response.body['response']

    if M2 != srp.verify(public_key, client_key, M1):
        logging.error('client password mismatch')
        raise StopIteration

    client_data = { 'key': aeskey,
                    'guid': session
                    }
    client_data.update( response.body )
    callback(client_data)


#def bytesToHex(bytes):
#    return ''.join( pad(hex(byte)[2:],2,'0') for byte in bytes )




import math

def ascii_to_hex(data):
    return ''.join([ pad( h[2:], 2, '0' ) for h in map(hex,map(ord,data)) ])


from util import make_post_body

@gen.engine
def test_login():
    username = sys.argv[1]
    password = sys.argv[2]

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
    token = parse_token(response.body)
    logging.info('got token %s' % token)

    args = { 'list': 1 }
    url = '%s/client/gui/?%s' % (result['host'], urllib.urlencode(args))

    logging.info( 'request %s' % url )
    headers, body = make_post_body(( { 'token': token, 't':int(time.time()*1000) } ))
    headers['x-bt-seq'] = str(cipher.ivoffset)
    encbody = ascii_to_hex( cipher.encrypt_pad( body ) ).upper()
    # convert to hex...
    headers['Content-Length'] = str(len(encbody))
    headers['Cookie'] = 'GUID=%s; bt_talon_tkt=%s' % (result['guid'], result['bt_talon_tkt'])

    request = Request('POST', url, headers = headers, body=encbody)
    response = yield gen.Task( make_request, request, expectjson=False, cipher=cipher )
    logging.info('list req response %s' % [response.body])


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

@gen.engine
def test_encrypt():
    #client_data={"cid":"7084730215","bt_talon_tkt":"dFYoaFcwFZFj+DRimt7+ggqh/DHFT2WNTEAqZyeM06gu8r0DunC7rKdcLcG5sqjw","bt_user":"kylepoo7","key":"4882e195ae736fad527d5aeef8b2ec75f0a1f66a","guid":"txU9bJxBRQI0azwiBrhw"}

    

    btseq = 292
    rawbody = [45, 45, 65, 97, 66, 48, 51, 120, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 68, 105, 115, 112, 111, 115, 105, 116, 105, 111, 110, 58, 32, 109, 117, 108, 116, 105, 112, 97, 114, 116, 47, 102, 111, 114, 109, 45, 100, 97, 116, 97, 59, 32, 110, 97, 109, 101, 61, 34, 116, 111, 107, 101, 110, 34, 13, 10, 13, 10, 101, 98, 107, 100, 84, 121, 68, 81, 113, 69, 108, 72, 105, 66, 56, 65, 115, 81, 83, 77, 54, 118, 107, 107, 89, 105, 113, 101, 108, 50, 67, 122, 117, 98, 104, 90, 113, 77, 81, 117, 107, 98, 69, 70, 116, 75, 81, 111, 65, 77, 70, 72, 100, 88, 120, 53, 76, 85, 56, 65, 65, 65, 65, 65, 13, 10, 45, 45, 65, 97, 66, 48, 51, 120, 13, 10, 13, 10, 13, 10]

    body = ''.join(map(chr,rawbody))
    logging.info('rawbody %s' % rawbody)
    result = client_data
    client_data['host'] = 'http://192.168.56.1:9090'
    cipher = Cipher(client_data['key'])
    cipher.ivoffset = btseq
    args = { 'list': 1 }
    url = '%s/client/gui/?%s' % (result['host'], urllib.urlencode(args))

    #headers, body = make_post_body(( { 'token': token, 't':int(time.time()*1000) } ))

    headers = {}
    headers['x-bt-seq'] = str(btseq)
    enc = cipher.encrypt( body )
    logging.info('%s' % map(ord, enc))

    encbody = ascii_to_hex( enc ).upper() # pad with some zeroes so that len % 16 == 0
    logging.info('hexenc %s' % encbody)

    if False:
        padto = 16*4

        if len(encbody) % padto != 0:
            encbodypad = encbody + '0' * (padto - (len(encbody)%padto))
        logging.info('hexencpad %s' % encbodypad)
    else:
        encbodypad = encbody

    # convert to hex...
    headers['Content-Length'] = str(len(encbodypad))
    headers['Cookie'] = 'GUID=%s; bt_talon_tkt=%s' % (result['guid'], result['bt_talon_tkt'])
    logging.info('req to url %s' % url)
    request = Request('POST', url, headers = headers, body=encbodypad)
    response = yield gen.Task( make_request, request, expectjson=False, cipher=cipher )
    logging.info('response %s' % [response.body])




if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    test_login()
    #test_decrypt()
    #test_encrypt()
    ioloop.start()
