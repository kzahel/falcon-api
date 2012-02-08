from session import Session
import logging
from util import asyncsleep
import json
import urllib
from tornado import gen
from tornado.options import options
if options.debug:
    import pdb

class BTFunction(object):
    #wire_string = '[native function]('
    wire_string = "[nf]("

    def __repr__(self):
        return '<BTFunc %s (%s)>' % (self.path[-1], ')('.join([','.join(defn) for defn in self.defn]))

    def __init__(self, btapp, path, defn):
        self.btapp = btapp
        self.path = path
        self.defn = self.parse_defn(defn)

    def parse_defn(self, defn):
        signatures = []

        start = 0
        while start < len(defn):
            i1 = defn.find('(', start)
            i2 = defn.find(')', start)
            argstr = defn[i1+1:i2]
            args = argstr.split(',')
            signatures.append(args)
            start = i2+1
        return signatures
            
    def check_args(self, args):
        matches = False
        return True
            

    @gen.engine
    def call(self, *args, **kwargs):
        self.check_args(args)

        logging.info('call bt func %s, %s with args %s' % (self.path, self.defn, str(args)))
        callargs = urllib.quote(json.dumps(args))
        fnargs = { 'btapp':self.btapp.app_str,
                   'type':'function',
                   'session': self.btapp.session_id,
                   'queries': json.dumps( [ '%s(%s)/' % ('/'.join(self.path), callargs) ] )
                   }
        #'queries': json.dumps(['btapp/settings/set(%s)/' % json.dumps(['dna.server_prefix','woobmpp'])])
        response = yield gen.Task( self.btapp.session.request, 
                                   'POST', '/client/gui/', 
                                   None, fnargs )
        kwargs['callback'](response)

        
class AppState(dict):
    def __init__(self, btapp, path=None, data=None):
        self.clean = True
        self.btapp = btapp
        self.path = path or []
        if data:
            self.add(data)

    def serialize(self):
        d = {}
        for k,v in self.items():
            if v.__class__ == AppState:
                d[k] = v.serialize()
            elif v.__class__ == BTFunction:
                d[k] = str(v)
            else:
                d[k] = v
        return d

    def add(self, data):
        #logging.info('add %s' % data)
        
        for k,v in data.items():
            if k not in self:
                if type(v) in [type(u''),type('')]:
                    if v.startswith(BTFunction.wire_string):
                        self[k] = BTFunction(self.btapp, self.path + [k], v)
                    else:
                        self[k] = v
                elif type(v) == type(0):
                    self[k] = v
                else:
                    self[k] = AppState(self.btapp, path=self.path + [k], data=v)
            else:
                if self[k].__class__ == AppState:
                    self[k].add( v )
                else:
                    self[k] = v

    def remove(self, data):
        # recursively remove data

        for k,v in data.items():
            if type(v) == type({}):
                if self[k].__class__ != AppState:
                    logging.error('state mismatch')
                    pdb.set_trace()
                
                self[k].remove( v )
                
            elif type(v) in [type(u''),type('')]:
                if self[k] != v:
                    logging.error('state mismatch')
                    pdb.set_trace()
                del self[k]

            elif type(v) == type(0):
                if self[k] != v:
                    logging.error('state mismatch')
                    pdb.set_trace()

            else:
                logging.error('unrecognized type')
                pdb.set_trace()
                    

class Btapp(object):
    def __init__(self, username=None, password=None, session=None):
        self.app_str = 'testapp'
        self.session_id = None
        self.username = username
        self.password = password
        self.session = session or Session()
        #self.state = LazyState()
        self.state = AppState(self)

    @gen.engine
    def sync(self, queries=None, callback=None):
        if not self.session.data and self.username and self.password:
            logging.info('logging in')
            yield gen.Task( self.session.login, self.username, self.password )
        
        if queries is None:
            queries = ['btapp/']
            #queries = ['btapp/torrent/all/*/peer/']
        
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

        self.session_id = response.body['result']['session']
        logging.info('got session id %s' % self.session_id)

        count = 0

        while True:
            args = { 'btapp':self.app_str,
                     'type':'update',
                     'session': self.session_id
                     }
            response = yield gen.Task( self.session.request, 
                                       'POST', '/client/gui/', 
                                       None, args )
            if set(response.body.keys()) == set(['result','build']) and not response.body['result']:
                pass
            else:
                logging.info('got resp %s' % json.dumps(response.body, indent=2))

                results = response.body['result']

                if 'error' in results:
                    if results['error'] == 'session has expired':
                        self.session_id = None
                    logging.error(results)
                else:

                    for result in results:

                        if set(result.keys()) != set(['add','remove']):
                            logging.error('more keys! %s' % result.keys())

                        if 'remove' in result and not self.state.clean:
                            self.state.remove(result['remove'])
                        if 'add' in result:
                            if self.state.clean:
                                self.state.clean = False
                            self.state.add(result['add'])
            
                        logging.info('state: %s' % json.dumps(self.state.serialize(),indent=2))

            yield gen.Task( asyncsleep, 1 )
            count += 1
            didcreate = False
            if count > 1 and not didcreate:

                btfn = self.state['btapp']['create']





                #btweb.bt['create']( 
                #function() { console.log('create callback'); },
                #name,
                #file_list,
                #_.bind(this.on_create_complete, this, time, view, message, log, cb), 
                #'share', 
                #'Created with Share');

                #yield gen.Task( btfn.call, '', ['C:\\spawnclients.log'], 'mycallback2', 'label','label' )

                didcreate = True

                if False:
                    btfn = self.state['btapp']['settings']['set']
                    if btfn.__class__ != BTFunction:
                        logging.error('serial value for function does not match?')
                        pdb.set_trace()
                    yield gen.Task( btfn.call, 'dna.server_prefix', 'test%s' % count )
                yield gen.Task( asyncsleep, 1 )
