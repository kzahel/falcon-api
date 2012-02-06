#!/usr/bin/env python
# messy first-run at falcon SRP key negotiation and aes ctr decryption
import urlparse
import logging
import socket
import re
import json
import urllib
import random
import time
from hashlib import sha1

import tornado.iostream
import tornado.ioloop
import tornado.options
from tornado.escape import utf8, _unicode, native_str
from tornado.util import b
from tornado.httputil import HTTPHeaders
from tornado import gen

import srp
from btcipher import Cipher
from util import pad, parse_token
from util import make_post_body, ascii_to_hex
from tornado.options import options
tornado.options.parse_command_line()
if 'srp_root' in options:
    SRP_ROOT = options.srp_root
else:
    SRP_ROOT = 'https://remote-staging.utorrent.com'

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

class ErrorResponse(object):
    def __init__(self, message):
        self.error = True
        self.message = message

class Response(object):
    def __init__(self, code, headers, body):
        self.code = code
        self.headers = headers
        self.body = body
        self.error = True if code >= 400 else False

class Request(object):
    def __init__(self, method, url, headers=None, body=None, cipher=None, expectjson=None):
        self.method = method
        self.url = url
        self.body = body
        self.cipher = cipher
        self.expectjson = expectjson
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

    def make_request_str(self, cipher=None):
        if self.body:
            if cipher:
                self.headers['x-bt-seq'] = str(cipher.ivoffset)
                body = ascii_to_hex( cipher.encrypt_pad( self.body ) ).upper()
            else:
                body = self.body
            self.headers['Content-Length'] = str(len(body))
            return self.make_request_headers() + body
        else:
            self.headers['Content-Length'] = str(0)
            return self.make_request_headers()

    def make_request_headers(self):
        if self.url_parsed.query:
            uri = '%s?%s' % (self.url_parsed.path, self.url_parsed.query)
        else:
            uri = self.url_parsed.path
        request_lines = [utf8("%s %s HTTP/1.1" % (self.method,
                                                  uri))]
        if 'Host' not in self.headers:
            self.headers["Host"] = self.url_parsed.netloc
        for k, v in self.headers.items():
            line = utf8(k) + b(": ") + utf8(v)
            request_lines.append(line)
        toreturn = b("\r\n").join(request_lines) + b("\r\n\r\n")
        return toreturn

    @gen.engine
    def make_request(self, expectjson=None, cipher=None, callback=None):
        # TODO -- use a connection pool
        cipher = cipher or self.cipher

        if self.expectjson is not None:
            expectjson = self.expectjson
        else:
            if expectjson is None:
                expectjson = True
            else:
                expectjson = expectjson

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = tornado.iostream.SSLIOStream(s) if self._conn_secure else tornado.iostream.IOStream(s)
        stream._always_callback = True
        addr = (self._conn_host, self._conn_port)
        yield gen.Task( stream.connect, addr )
        if stream.error:
            logging.error('could not go :-(')
            raise StopIteration
        yield gen.Task( stream.write, self.make_request_str(cipher=cipher) )
        if stream.error:
            logging.error('could not go :-(')
            raise StopIteration
        rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )
        code, headers = parse_headers(rawheaders)
        body = yield gen.Task( stream.read_bytes, int(headers['Content-Length']) )
        stream.close()
        if not body:
            logging.error('conn closed reading for body?')
            raise StopIteration
        if cipher:
            if 'X-Bt-Seq' not in headers:
                logging.error('no encryption sequence in response %s, %s' % (code, headers))
                raise StopIteration
            cipher.ivoffset = int(headers['X-Bt-Seq'])
            logging.info('got headers %s' % headers)
            encbody = body
            body = cipher.encrypt_pad(cipher.hex_to_ascii(body))
            body = cipher.remove_trailing_nulls( body )
            # TODO -- need to figure out which encoding this is in
        if expectjson:
            data = json.loads(body)
        else:
            data = body
        callback( Response(code, headers, data) )
    


class Session(object):
    def __init__(self):
        self.data = None
        self.token = None

    @gen.engine
    def login(self, username, password, callback=None):
        # TODO - invoke callback when errors occur
        args = {'user': username}
        request = Request('GET', '%s/api/login/?%s' % (options.srp_root, urllib.urlencode(args)))
        response = yield gen.Task( request.make_request )
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
        response = yield gen.Task( request.make_request )
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
        response = yield gen.Task( request.make_request )
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

        self.data = client_data
        self.cipher = Cipher(client_data['key'])
        if callback:
            callback(client_data)

    def get_auth_args(self):
        return {'GUID': self.data['guid'],
                'bt_talon_tkt': self.data['bt_talon_tkt']}

    @gen.engine
    def get_token(self, callback=None):
        if not self.data:
            callback( ErrorResponse("haven't logged in") )
            raise StopIteration

        args = self.get_auth_args()
        url = '%s/client/gui/token.html?%s' % (self.data['host'], urllib.urlencode(args))
        request = Request('GET',url, cipher=self.cipher, expectjson=False )
        response = yield gen.Task( request.make_request )
        self.token = parse_token(response.body)
        callback(response)
    
    @gen.engine
    def request(self, method, base_url, url_params, body_params=None, callback=None):
        if not self.data:
            callback( ErrorResponse("haven't logged in") )
            raise StopIteration

        if not self.token:
            yield gen.Task( self.get_token )
            

        args = self.get_auth_args()
        if url_params:
            args.update( url_params )

        url = '%s%s?%s' % ( self.data['host'], base_url, urllib.urlencode(args) )

        body_data = { 'token': self.token, 't':int(time.time()*1000) }
        if body_params:
            body_data.update( body_params )
        headers, body = make_post_body( body_data )
        headers['Cookie'] = 'GUID=%s; bt_talon_tkt=%s' % (self.data['guid'], self.data['bt_talon_tkt'])
        request = Request(method, url, headers=headers, body=body, cipher=self.cipher)
        response = yield gen.Task( request.make_request )
        callback(response)
