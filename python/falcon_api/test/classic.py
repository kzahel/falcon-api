import sys
import time
import json
import logging
import random
import tornado.options
from tornado.options import define, options
from tornado import gen

define('srp_root',default='http://192.168.56.1')
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
from falcon_api.classic import Client

@gen.engine
def test_login():
    username = sys.argv[1]
    password = sys.argv[2]

    # check result..
    #torrent = 'http://www.clearbits.net/get/503-control-alt-deus---made-of-fire.torrent'
    hash = ''.join([random.choice( list('abcdef') + map(str,range(10)) ) for _ in range(40)])
    torrent = 'magnet:?xt=urn:btih:%s' % hash

    client = Client(username, password)
    client.sync()

    yield gen.Task( asyncsleep, 4 )
    #client.add_url(torrent)

    for hash, torrent in client.torrents.items():
        print torrent.get('name')


if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    test_login()
    ioloop.start()
