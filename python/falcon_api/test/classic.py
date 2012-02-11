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
import tornado.httpclient 

httpclient = tornado.httpclient.AsyncHTTPClient(force_instance=True, max_clients=1)

@gen.engine
def test_login():
    username = sys.argv[1]
    password = sys.argv[2]

    # check result..
    #torrent = 'http://www.clearbits.net/get/503-control-alt-deus---made-of-fire.torrent'
    hash = ''.join([random.choice( list('abcdef') + map(str,range(10)) ) for _ in range(40)])
    torrent = 'magnet:?xt=urn:btih:%s' % hash

    for _ in range(1):
        client = Client(username, password)
        client.sync()
        yield gen.Task( asyncsleep, 1 )
    #client.add_url(torrent)

    client.stop()

    tasks = []
    for hash, torrent in client.torrents.items():
        if torrent.get('progress') == 1000:
            tasks.append( gen.Task( torrent.fetch_files ) )
            tasks.append( gen.Task( torrent.fetch_metadata ) )
    responses = yield gen.Multi( tasks )
    logging.info('responses %s' % [r.code for r in responses])

    tasks = []
    for hash, torrent in client.torrents.items():
        if torrent.get('progress') == 1000:
            for file in torrent.files:
                link = file.webseed_link()
                print link
                request = tornado.httpclient.HTTPRequest(link,
                                                         validate_cert=False)
                tasks.append( gen.Task( httpclient.fetch, request ) )

    while tasks:
        some_tasks = [tasks.pop() for _ in range(5)]
        logging.info('executing tasks of len %s' % len(some_tasks))
        responses = yield gen.Multi( some_tasks )
        logging.info('responses %s' % [(r.code, len(r.body)) for r in responses])



    if False:
        tasks = []
        for hash, torrent in client.torrents.items():
            if torrent.get('progress') == 1000:
                link = torrent.webseed_link()

                print torrent.get('name'), torrent.get('progress'), link

                request = tornado.httpclient.HTTPRequest(link,
                                                         validate_cert=False)
                tasks.append( gen.Task( httpclient.fetch, request ) )
        responses = yield gen.Multi( tasks )
        logging.info('responses %s' % [r.code for r in responses])

if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    test_login()
    ioloop.start()
