import sys
import time
import json
import logging
import random
import tornado.options
from tornado.options import define, options
from tornado import gen

define('srp_root',default='http://192.168.56.1')
define('server_address',default='http://192.168.56.101:36440')
#define('srp_root',default='https://remote-staging.utorrent.com')
#define('srp_root',default='https://remote.utorrent.com')
define('debug',default=True)
define('verbose',default=1, type=int)
tornado.options.parse_command_line()
if options.debug:
    import pdb

import tornado.ioloop
from falcon_api.session import Session
from falcon_api.util import asyncsleep

@gen.engine
def test_login():
    username = sys.argv[1]
    password = sys.argv[2]

    session = Session()

    session.endpoint = '/gui/srp'
    session.srp_direct = options.server_address
    session.enable_direct()

    result = yield gen.Task( session.login, username, password )
    logging.info('got session %s' % result)

    result = yield gen.Task( session.get_token )

    logging.info('got token %s %s' % (result, session.token))

    # check result..
    old_style = True
    btappstr = 'testbtapp'
    #torrent = 'http://www.clearbits.net/get/503-control-alt-deus---made-of-fire.torrent'
    hash = ''.join([random.choice( list('abcdef') + map(str,range(10)) ) for _ in range(40)])
    torrent = 'magnet:?xt=urn:btih:%s' % hash


    cid = None
    count = 0
    while count < 10:
        count += 1
        #url_args = {'list':1}
        url_args = None
        #args = {}
        args = { 'list': 1 }
        if cid:
            args['cid'] = cid
        response = yield gen.Task( session.request, 'GET', url_params=url_args, body_params=args )
        #logging.info('got response %s' % response)
        if 'torrentc' in response.body:
            cid = response.body['torrentc']
        logging.info('list req response %s' % [response.body])
        yield gen.Task(asyncsleep,1)
        assert response.code == 200

    logging.info('woot!')

    ioloop.stop()
    #args = { 'action': 'add-url', 's': torrent }
    #response = yield gen.Task( session.request, 'GET', None, args )



if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    test_login()
    ioloop.start()
