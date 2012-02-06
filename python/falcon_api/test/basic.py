import tornado.options
from tornado.options import define, options
from tornado import gen
import sys
import logging
define('srp_root',default='http://192.168.56.1:9090')
#define('srp_root',default='https://remote-staging.utorrent.com')
define('debug',default=True)
tornado.options.parse_command_line()

import tornado.ioloop
from falcon_api.session import Session

@gen.engine
def test_login():
    username = sys.argv[1]
    password = sys.argv[2]

    session = Session()
    result = yield gen.Task( session.login, username, password )

    old_style = True
    if old_style:

        response = yield gen.Task( session.request, 'POST', '/client/gui/', { 'list': 1 } )
        logging.info('list req response %s' % [response.body])

    else:
        args = { 'btapp': 'backbone.btapp.js' }

        body_args = {}
        json.dumps( body_args )

        url = '%s/client/gui/?%s' % (result['host'], urllib.urlencode(args))
            
        request = Request('POST', url, headers = headers, body=body)


if __name__ == '__main__':
    ioloop = tornado.ioloop.IOLoop.instance()
    test_login()
    ioloop.start()
