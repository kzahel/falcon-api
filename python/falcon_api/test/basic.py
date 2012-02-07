import sys
import time
import json
import logging

import tornado.options
from tornado.options import define, options
from tornado import gen

#define('srp_root',default='http://192.168.56.1:9090')
#define('srp_root',default='https://remote-staging.utorrent.com')
define('srp_root',default='https://remote.utorrent.com')
define('debug',default=True)
define('verbose',default=1, type=int)
tornado.options.parse_command_line()
if options.debug:
    import pdb

import tornado.ioloop
from falcon_api.session import Session

@gen.engine
def test_login():
    username = sys.argv[1]
    password = sys.argv[2]

    session = Session()
    result = yield gen.Task( session.login, username, password )

    old_style = False
    btappstr = 'testbtapp'

    if old_style:

        response = yield gen.Task( session.request, 'POST', '/client/gui/', { 'list': 1 } )
        logging.info('list req response %s' % [response.body])

        response = yield gen.Task( session.request, 'POST', '/client/gui/', { 'list': 1 } )
        logging.info('list req response %s' % [response.body])

    else:
        args = { 'btapp':btappstr,
                 'type':'state',
                 'queries': json.dumps(['btapp/'])
                 }
        response = yield gen.Task( session.request, 
                                   'POST', '/client/gui/', 
                                   None, args )
        sessid = response.body['result']['session']
        logging.info('btapp response %s' % [response.body])

        args = { 'btapp':btappstr,
                 'type':'update',
                 'session': sessid
                 }
        response = yield gen.Task( session.request, 
                                   'POST', '/client/gui/', 
                                   None, args )

        logging.info('btapp response w keys %s' % response.body.keys())

        fo = open('out.js','w')
        fo.write( json.dumps(response.body, indent=2) )
        fo.close()

        # 22907
        args = { 'btapp':btappstr,
                 'type':'function',
                 'session': sessid,
#                  'queries': json.dumps(['btapp/settings/set(%s)/' % json.dumps(['bind_port',22909])])
#                  'queries': json.dumps(['btapp/settings/set(%s)/' % json.dumps(['bt.allow_same_ip',True])])
#                  'queries': json.dumps(['btapp/settings/set(%s)/' % json.dumps(['dna.server_prefix','poopy'])])
                  'queries': json.dumps(['btapp/settings/set(%s)/' % json.dumps(['dna.server_prefix','woobmpp'])])
                 }
        response = yield gen.Task( session.request, 
                                   'POST', '/client/gui/', 
                                   None, args )

        logging.info('btapp set response %s' % response.code)



if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    test_login()
    ioloop.start()
