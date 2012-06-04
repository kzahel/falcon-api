import random
import string
import tornado.ioloop
import time

def random_string (length):
    return 'AaB03x'
    return ''.join (random.choice (string.letters) for ii in range (length + 1))
def encode_field (field_name, data, boundary):
    return ('--' + boundary,
            'Content-Disposition: multipart/form-data; name="%s"' % field_name,
            '', str (data [field_name]))

def encode_multipart_data(data):
    boundary = random_string (30)

    lines = []
    for name in data:
        lines.extend (encode_field (name, data, boundary))
    lines.extend (('--%s--' % boundary, ''))
    body = '\r\n'.join (lines)

    headers = {'Content-Type': 'application/octet-stream; boundary=' + boundary + '; charset=ascii'}


    return headers, body


boundary = 'AaB03x'

def make_part(v,k):
    return 'Content-Disposition: multipart/form-data; name="' + k + '"\r\n\r\n' + str(v) + '\r\n';

def make_post_body(params):
    body = '--' + boundary + '\r\n'
    bodyparts = []
    for key,val in params.items():
        if type(val) == type([]):
            for item in val:
                bodyparts.append( make_part(item, key) )
        else:
            bodyparts.append( make_part(val, key) )
    body += ('--' + boundary + '\r\n').join(bodyparts)
    body += '--' + boundary + '\r\n\r\n\r\n'
    headers = {'Content-Type': 'application/octet-stream; boundary=' + boundary + '; charset=ascii'}
    return headers, body

def pad(s,width,padwith):
    if len(s) < width:
        return (padwith * (width-len(s))) + s
    elif len(s) > width:
        raise Exception('cant pad..too wide')
    else:
        return s

def parse_token(body):
    begstr = "style='display:none;'>"
    endstr = "</div>"
    i1 = body.index(begstr)
    i2 = body.index(endstr)
    return body[i1+len(begstr):i2]

def ascii_to_hex(data):
    return ''.join([ pad( h[2:], 2, '0' ) for h in map(hex,map(ord,data)) ])

def asyncsleep(t, callback=None):
    tornado.ioloop.IOLoop.instance().add_timeout( time.time() + t, callback )
