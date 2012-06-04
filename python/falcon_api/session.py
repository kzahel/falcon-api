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
import random
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

def random_cut(str):
    if random.random() < 0.5:
        return str[:random.randrange(0,len(str))]
    else:
        return str

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
    def __repr__(self):
        return '<ErrorResponse: %s>' % self.message

class Response(object):
    def __init__(self, code, headers, body):
        self.code = code
        self.headers = headers
        self.body = body
        self.error = True if code >= 400 else False

class Request(object):
    def __init__(self, method, url, headers=None, body=None, cipher=None, expectjson=None, jsonp=True):
        self.jsonp = jsonp
        self.method = method
        self.url = url
        self.body = body
        self.cipher = cipher
        self.expectjson = expectjson
        self.url_parsed = urlparse.urlsplit(url)
        self.url_parsed.use_query = self.url_parsed.query # .query is read only attribute
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

        self.addr = (self._conn_host, self._conn_port)

        self.headers = headers or {}

    def make_request_str(self, cipher=None):
        ivoffset = str(cipher.ivoffset) if cipher else None
        body = None

        if self.body:
            if cipher:
                body = ascii_to_hex( cipher.encrypt_pad( self.body ) ).upper()
            else:
                body = self.body
            if self.jsonp:
                # modify url...
                if self.url_parsed.use_query:
                    self.url_parsed.use_query += ('&encbody=%s&x_bt_seq=%s' % (body, ivoffset))
                    #self.url_parsed.use_query += ('&encbody=%s' % body)
                    #self.headers['x-bt-seq'] = str(cipher.ivoffset)
                body = None
            else:
                self.headers['x-bt-seq'] = ivoffset

        if body:
            self.headers['Content-Length'] = str(len(body))
            return self.make_request_headers() + body
        else:
            self.headers['Content-Length'] = str(0)
            return self.make_request_headers()

    def make_request_headers(self, cipher=None):
        if self.url_parsed.use_query:
            uri = '%s?%s' % (self.url_parsed.path, self.url_parsed.use_query)
            if cipher:
                uri += '&x_bt_seq=%s' % cipher.ivoffset
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
    def make_request(self, expectjson=None, cipher=None, simulate_crappy_network=False, callback=None):
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
            logging.error('could not connect to %s' % str(addr))
            callback( ErrorResponse('could not connect') )
            raise StopIteration
        if simulate_crappy_network and random.random() < 0.1:
            logging.info('simulate crap')
            yield gen.Task( stream.write, random_cut(self.make_request_str(cipher=cipher)) )
            stream.close()
            callback( ErrorResponse('simulate crappy network') )
            raise StopIteration
        req = self.make_request_str(cipher=cipher)
        logging.info('make request %s %s' % (addr, req))
        yield gen.Task( stream.write, req )
        if stream.error:
            logging.error('could not write request')
            callback( ErrorResponse('could not write request') )
            raise StopIteration
        rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )
        code, headers = parse_headers(rawheaders)
        if not code or not headers and options.debug:
            pdb.set_trace()
        if simulate_crappy_network and random.random() < 0.2:
            yield gen.Task( stream.read_bytes, random.randrange(1, int(headers['Content-Length'])) )
            stream.close()
            callback( ErrorResponse('simulate hangup on body read') )
            raise StopIteration
        body = yield gen.Task( stream.read_bytes, int(headers['Content-Length']) )
        stream.close()
        if not body:
            callback( ErrorResponse('body not read') )
            logging.error('conn closed reading for body?')
            raise StopIteration
        if cipher:
            if 'X-Bt-Seq' not in headers:
                logging.error('no encryption sequence in response %s, %s' % (code, headers))
                pdb.set_trace()
                callback( ErrorResponse('no enc seq found') )
                raise StopIteration
            cipher.ivoffset = int(headers['X-Bt-Seq'])
            encbody = body
            body = cipher.encrypt_pad(cipher.hex_to_ascii(body))
            body = cipher.remove_trailing_nulls( body )
            # TODO -- need to figure out which encoding this is in
        if expectjson:
            data = json.loads(body)
        else:
            data = body
        if options.verbose > 0:
            logging.info('%s %s %s?%s' % (self.method, code, self.url_parsed.path, self.url_parsed.use_query))
        callback( Response(code, headers, data) )
    


class Session(object):
    def __init__(self):
        self.data = None
        self.token = None
        self._simulate_crappy_network = False # randomly close the stream at different times
        self._direct = False
        self._use_cookie = False
        self.cipher = None

    def enable_direct(self):
        self._direct = True

    def debug(self):
        logging.info('debug %s cipher %s' % (self, self.cipher.ivoffset))

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
        args = {'GUID': self.data['guid']}
        if not self._direct:
            args['bt_talon_tkt'] = self.data['bt_talon_tkt']
        #if self.token:
        #    args['token'] = self.token
        return args

    def get_base_url(self):
        if self._direct:
            return '/gui/'
        else:
            return '/client/gui/'

    def get_host(self):
        if self._direct:
            return 'http://%s:%s' % (self.data['ip'], self.data['port'])
        else:
            return self.data['host']

    @gen.engine
    def get_token(self, direct=False, callback=None):
        if not self.data:
            callback( ErrorResponse("haven't logged in") )
            raise StopIteration

        args = self.get_auth_args()
        if direct:
            url = '%s%stoken.html?%s' % (self.get_host(), self.get_base_url(), urllib.urlencode(args))
        else:
            url = '%s%stoken.html?%s' % (self.data['host'], '/client/gui/', urllib.urlencode(args))
        request = Request('GET',url, cipher=self.cipher, expectjson=False )
        response = yield gen.Task( request.make_request )
        self.token = parse_token(response.body)
        callback(response)
    
    @gen.engine
    def request(self, method='POST', url_params=None, body_params=None, jsonp=True, callback=None):
        if not self.data:
            callback( ErrorResponse("haven't logged in") )
            raise StopIteration

        if not self.token:
            yield gen.Task( self.get_token )
            

        args = self.get_auth_args()

        if self._use_cookie:
            headers['Cookie'] = 'GUID=%s; bt_talon_tkt=%s' % (self.data['guid'], self.data['bt_talon_tkt'])

        if url_params:
            args.update( url_params )

        url = '%s%s?%s' % ( self.get_host(), self.get_base_url(), urllib.urlencode(args) )

        if self.token:
            body_data = { 'token': self.token, 't':int(time.time()*1000) }
            #body_data = { 'token': self.token }
        else:
            pdb.set_trace()
        #body_data = { 't':int(time.time()*1000) }
        if body_params:
            body_data.update( body_params )
        #logging.info('encrypting body data %s %s' % (self.cipher.ivoffset, body_data))
        headers, body = make_post_body( body_data )
        #logging.info('making post body %s' % body)
        if jsonp:
            headers = None

        request = Request(method, url, headers=headers, body=body, cipher=self.cipher, jsonp=jsonp)
        response = yield gen.Task( request.make_request, simulate_crappy_network=self._simulate_crappy_network )
        callback(response)

