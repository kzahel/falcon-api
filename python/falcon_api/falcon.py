from tornado.options import options
from tornado import gen
import urllib
import bencode
if options.debug:
    import pdb

import tornado.httpclient 
httpclient = tornado.httpclient.AsyncHTTPClient(force_instance=True, max_clients=5)

class Torrent(object):

    def webseed_link(self):
        url = '%s/talon/seed/%s/content/%s' % (self.client.session.data['host'],
                                               self.client.session.data['cid'],
                                               self.get('stream_id'))
        return url

    @gen.engine
    def fetch_metadata(self, callback=None):
        url = '%s/talon/seed/%s/torrent/%s' % (self.client.session.data['host'],
                                               self.client.session.data['cid'],
                                               self.get('stream_id'))
        request = tornado.httpclient.HTTPRequest(url, validate_cert=False)
        response = yield gen.Task( httpclient.fetch, request )
        self.meta = bencode.bdecode(response.body)
        callback( response )


class File(object):

    def webseed_link(self):
        # the name attribute sucks... it contains the local file path.
        # have to webseed fetch the torrent metadata
        if 'files' in self.torrent.meta['info']:
            path = self.torrent.meta['info']['files'][self.index]['path']
            try:
                return '%s/%s/%s' % (self.torrent.webseed_link().encode('ascii'), 
                                     urllib.quote(self.torrent.get('name').encode('ascii')),
                                     urllib.quote('/'.join(path)))
            except:
                pdb.set_trace()
        else:
            name = self.torrent.meta['info']['name']
            return '%s/%s' % (self.torrent.webseed_link(), name)
