from session import Session
import logging
from util import asyncsleep
import json
from tornado import gen

class Btapp(object):
    def __init__(self, username=None, password=None, session=None):
        self.app_str = 'testapp'
        self.id = None
        self.username = username
        self.password = password
        self.session = session or Session()

    @gen.engine
    def sync(self, queries=None, callback=None):
        if not self.session.data and self.username and self.password:
            logging.info('logging in')
            yield gen.Task( self.session.login, self.username, self.password )
        
        if queries is None:
            queries = ['btapp/']
        
        args = { 'btapp':self.app_str,
                 'type':'state',
                 'queries': json.dumps(queries)
                 }
        response = yield gen.Task( self.session.request,
                                   'POST', 
                                   '/client/gui/', 
                                   None, 
                                   args )
        if response.code != 200 or 'result' not in response.body or 'session' not in response.body['result']:
            logging.error('could not get session')
            raise StopIteration

        self.id = response.body['result']['session']
        logging.info('got session id %s' % self.id)

        while True:
            args = { 'btapp':self.app_str,
                     'type':'update',
                     'session': self.id
                     }
            response = yield gen.Task( self.session.request, 
                                       'POST', '/client/gui/', 
                                       None, args )
            #logging.info('got resp %s' % json.dumps(response.body, indent=2))

            yield gen.Task( asyncsleep, 1 )
