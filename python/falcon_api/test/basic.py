import tornado.options
from tornado.options import define, options
from tornado import gen
import sys
import time
import json
import logging
define('srp_root',default='http://192.168.56.1:9090')
#define('srp_root',default='https://remote-staging.utorrent.com')
define('debug',default=True)
tornado.options.parse_command_line()
if options.debug:
    import pdb

import tornado.ioloop
from falcon_api.session import Session

def asyncsleep(t, callback=None):
    logging.info('sleeping %s' % t)
    tornado.ioloop.IOLoop.instance().add_timeout( time.time() + t, callback )

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

        logging.info('btapp response %s' % [response.body])




if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    test_login()
    ioloop.start()
