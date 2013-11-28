"""Dailymotion Cloud RPC loosely based on JSON-RPC
Removed the dependancy of pycurl
"""

from __future__ import print_function

import sys

API_ENDPOINT = '/api'

__version__ = "1.2.6"
__python_version__ = '.'.join([str(i) for i in sys.version_info[:3]])
_DEBUG = False

import os
#import StringIO
import string
import random
import hashlib
import datetime
import time
#import pycurl
import urllib2
import zlib
import re
import base64
import urllib
try:
    import json
except ImportError:
    import simplejson as json

#
# Common
#
class SecLevel:
    NONE = 0
    DELEGATE = 1 << 0
    ASNUM = 1 << 1
    IP = 1 << 2
    USERAGENT = 1 << 3
    USEONCE = 1 << 4
    COUNTRY = 1 << 5
    REFERER = 1 << 6
    REFERER_STRICT = 1 << 15

def sign_url(url, secret, seclevel=None, asnum=None, ip=None, useragent=None, countries=None, referers=None, expires=None):
    # Normalize parameters
    seclevel = seclevel or SecLevel.NONE
    expires = int(expires or time.time() + 7200)

    # Compute digest
    (url, unused, query) = url.partition('?')
    secparams = ''
    public_secparams = []
    if not seclevel & SecLevel.DELEGATE:
        if seclevel & SecLevel.ASNUM:
            if not asnum:
                raise ValueError('ASNUM security level required and no AS number provided.')
            secparams += asnum
        if seclevel & SecLevel.IP:
            if not ip:
                raise ValueError('IP security level required and no IP address provided.')
            secparams += ip
        if seclevel & SecLevel.USERAGENT:
            if not useragent:
                raise ValueError('USERAGENT security level required and no user-agent provided.')
            secparams += useragent
        if seclevel & SecLevel.COUNTRY:
            if not countries or len(countries) == 0:
                raise ValueError('COUNTRY security level required and no coutry list provided.')
            if type(countries) is not list:
                raise ValueError('Invalid format for COUNTRY, should be a list of country codes.')
            if countries[0] == '-':
                countries = '-' + ','.join(countries[1:])
            else:
                countries = ','.join(countries)
            if not re.match(r'^-?(?:[a-zA-Z]{2})(?:,[a-zA-Z]{2})*$', countries):
                raise ValueError('Invalid format for COUNTRY security level parameter.')
            public_secparams.append('cc=%s' % countries.lower())
        if seclevel & SecLevel.REFERER or seclevel & SecLevel.REFERER_STRICT:
            if not referers or len(referers) == 0:
                raise ValueError('REFERER security level required and no referer list provided.')
            if type(referers) is not list:
                raise ValueError('Invalid format for REFERER, should be a list of url strings.')
            public_secparams.append('rf=%s' % urllib.quote_plus(' '.join(
                [referer.replace(' ', '%20') for referer in referers])))

    public_secparams_encoded = ''
    if len(public_secparams) > 0:
        public_secparams_encoded = base64.urlsafe_b64encode(zlib.compress('&'.join(public_secparams)))
    rand = ''.join(random.choice(string.ascii_lowercase + string.digits) for unused in range(8))
    digest = hashlib.md5('%d%s%d%s%s%s%s' % (seclevel, url, expires, rand, secret, secparams, public_secparams_encoded)).hexdigest()

    # Return signed URL
    return '%s?%sauth=%s-%s-%s-%s%s' % (url, (query + '&' if query else ''), expires, seclevel, rand, digest, ('-' + public_secparams_encoded if public_secparams_encoded else ''))

def normalize(arg=None):
    """Normalizes an argument for signing purpose.

    This is used for normalizing the arguments of RPC method calls.

    :param arg: The argument to normalize

    :return: A string representating the normalized argument.

    .. doctest::

     >>> normalize(['foo', 42, 'bar'])
     'foo42bar'
     >>> normalize({'yellow': 1, 'red': 2, 'pink' : 3})
     'pink3red2yellow1'
     >>> normalize(['foo', 42, {'yellow': 1, 'red': 2, 'pink' : 3}, 'bar'])
     'foo42pink3red2yellow1bar'
     >>> normalize(None)
     ''
     >>> normalize([None, 1,2])
     '12'
     >>> normalize({2: [None, 1,2], 3: None, 4:5})
     '212345'
    """
    res = ''

    t_arg = type(arg)
    if t_arg in (list, tuple):
        for i in arg:
            res += normalize(i)
    elif t_arg is dict:
        keys = arg.keys()
        keys.sort()
        for key in keys:
            res += '%s%s' % (normalize(key), normalize(arg[key]))
    elif t_arg is unicode:
        res = arg.encode('utf8')
    elif t_arg is bool:
        res = 'true' if arg else 'false'
    elif arg != None:
        res = str(arg)

    return res

def sign(shared_secret, msg):
    """Signs a message using a shared secret.

    :param shared_secret: The shared secret used to sign the message
    :param msg: The message to sign

    :return: The signature as a string

    .. doctest::

     >>> sign('sEcReT_KeY', 'hello world')
     'b5d93121a6dc87562b46beb8ba809ace'

     old result was:
     '5f048ebaf6f06576b60716dc8f815d85'
     docstring not updated in API
    """
    if isinstance(msg, unicode):
        msg = msg.encode('utf8')
    return hashlib.md5(msg + shared_secret).hexdigest()

DRM_TOKEN_TIMEOUT = 600

def gen_drm_token(user_id, media_id, api_key, rights=None, meta=None, callback_url=None, expires=0, max_replay=0, encode=True):
    info = {
        'user_id': user_id,
        'media_id': media_id,
        'expires': expires if expires and isinstance(expires, int) else int(time.time() + DRM_TOKEN_TIMEOUT),
        'nonce': base64.urlsafe_b64encode(os.urandom(8)),
    }
    if max_replay and isinstance(max_replay, int):
        info['max_replay'] = max_replay
    if isinstance(rights, dict):
        info['rights'] = rights
    if isinstance(meta, dict):
        info['meta'] = meta
    if isinstance(callback_url, (str, unicode)):
        info['callback_url'] = callback_url

    info['auth'] = sign(api_key, normalize(info))

    payload = json.dumps(info)
    if encode:
        return base64.urlsafe_b64encode(payload)
    return payload

#################################################################################
class RPCException(Exception):
    """Base class for all RPC exceptions.
    """
    code = 100

    def __init__(self, message, data=None):
        self.message = message
        self.data = data

    def __str__(self):
        msg = '%d: %s' % (self.code, self.message)
        if self.data:
            msg = '%s [%s]' % (msg, self.data)
        return msg

class ProcessorException(RPCException):
    """Base class for all Processor exceptions
    """
    code = 200

class TransportException(RPCException):
    """Exceptions in transport layer
    """
    code = 300

class AuthenticationError(RPCException):
    """Base class for all Auth exceptions.
    """
    code = 400

class RateLimitExceeded(AuthenticationError):
    code = 410

class SerializerError(RPCException):
    code = 500

class InvalidRequest(RPCException):
    code = 600

class InvalidObject(InvalidRequest):
    code = 610

class InvalidMethod(InvalidRequest):
    code = 620

class InvalidParameter(InvalidRequest):
    code = 630

class InvalidCall(InvalidRequest):
    code = 640

class MissingParameter(InvalidRequest):
    code = 650

class ApplicationException(RPCException):
    code = 1000

class NotFound(ApplicationException):
    code = 1010

class Exists(ApplicationException):
    code = 1020

class LimitExceeded(ApplicationException):
    code = 1030

def RPCException_handler(error):
    # TODO Autogenerate this dict by introspection
    exceptions = {
        200: ProcessorException,
        300: TransportException,
        400: AuthenticationError,
        410: RateLimitExceeded,
        500: SerializerError,
        600: InvalidRequest,
        610: InvalidObject,
        620: InvalidMethod,
        630: InvalidParameter,
        640: InvalidCall,
        650: MissingParameter,
        1000: ApplicationException,
        1010: NotFound,
        1020: Exists,
        1030: LimitExceeded,
        }

    e = exceptions.get(error['code'])
    if not e:
        e = RPCException
        e.code = error['code']
    return e(error['message'], error.get('data', None))


class JSONEncoder(json.JSONEncoder):
    """Extends JSON encoder to handle types like datetime

    .. doctest::

     >>> import json
     >>> from datetime import datetime
     >>> my_date = datetime(year=2010, month=4, day=11)
     >>> json.dumps(my_date, cls=JSONEncoder)
     '1270936800'
    """
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return int(time.mktime(obj.timetuple()))
        return json.JSONEncoder.default(self, obj)


class dotdict(dict):
    def __getattr__(self, attr):
        return self.get(attr, None)

class ClientObject(object):

    def __init__(self, client, name):
        self._client = client
        self._name = name

    def __getattr__(self, method):
        global _DEBUG

        def func(**kwargs):
            request = {
                'call': '%s.%s' % (self._name, method),
                'args': kwargs,
                }

            if not self._client._act_as_user:
                user_infos = self._client._user_id
            else:
                user_infos = "%s/%s" % (self._client._user_id, self._client._act_as_user)
            request['auth'] = user_infos + ':' + sign(self._client._api_key, user_infos + normalize(request))


            #c = pycurl.Curl()
            proxy = urllib2.ProxyHandler(self._client._proxy)
            opener = urllib2.build_opener(proxy)
            opener.addheader = ('User-agent', 'cloudkey-py/%s (Python %s)' %
                                  (__version__, __python_version__))
            #c.setopt(pycurl.URL, str(self._client._api_endpoint))
            #c.setopt(pycurl.USERAGENT, 'cloudkey-py/%s (Python %s)' % (__version__, __python_version__))
            #c.setopt(pycurl.HTTPHEADER, ["Content-Type: application/json", 'Expect:'])
            opener.addheader = ("Content-Type: application/json", 'Expect:')

            if _DEBUG:
                print('   Example request::')
                print('')
                print('   Normalization or request: ' + normalize(request))
                print('')
                for line in  json.dumps(request, cls=JSONEncoder, indent=2).split('\n'):
                    print(('       %s' % line))
                print('')

            try:
                data = json.dumps(request, cls=JSONEncoder)
            except (TypeError, ValueError), e:
                raise SerializerError(str(e))

            #c.setopt(pycurl.POSTFIELDS, data)

            #if self._client._proxy:
                #c.setopt(pycurl.PROXY, self._client._proxy)

            #response = io.StringIO()
            #c.setopt(pycurl.WRITEFUNCTION, response.write)

            try:
                response = opener.open(self._client._api_endpoint, data)
                response_msg = response.read()
                #c.perform()
            except urllib2.URLError, e:
                raise TransportException(str(e))
            finally:
                #c.close()
                response.close()

            try:
                #msg = json.loads(response.getvalue(), object_hook=lambda x: dotdict(x))
                #msg = json.loads(response.getvalue())
                msg = json.loads(response_msg)
                if _DEBUG:
                    print('   Example response::')
                    print('')
                    for line in  json.dumps(msg, indent=2).split('\n'):
                        print('       %s' % line)
                    print('')
            except (TypeError, ValueError), e:
                raise SerializerError(str(e))
            error = msg.get('error', None)
            if error:
                raise RPCException_handler(error)
            return msg.get('result')

        return func


class FileObject(ClientObject):
    pass

#    def upload_file(self, file, progress = None):
#        if not os.path.exists(file):
#            raise IOError("[Errno 2] No such file or directory: '%s'" % file)
#        result = self.upload()
#
#        if isinstance(file, str):
#            file = file.encode('utf8')
#
#        c = pycurl.Curl()
#        c.setopt(pycurl.URL, str(result['url']))
#        c.setopt(pycurl.USERAGENT, 'cloudkey-py/%s (Python %s)' % (__version__, __python_version__))
#        c.setopt(pycurl.HTTPHEADER, ['Expect:'])
#        c.setopt(pycurl.FOLLOWLOCATION, True)
#        c.setopt(pycurl.HTTPPOST, [('file', (pycurl.FORM_FILE, file))])
#
#        if self._client._proxy:
#            c.setopt(pycurl.PROXY, self._client._proxy)
#
#        if progress:
#            c.setopt(pycurl.NOPROGRESS, 0)
#            c.setopt(pycurl.PROGRESSFUNCTION, lambda x, y, total, current: progress(current, total))
#
#        response = io.StringIO()
#        c.setopt(pycurl.WRITEFUNCTION, response.write)
#
#        try:
#            c.perform()
#        except pycurl.error as e:
#            raise TransportException(str(e))
#        c.close()
#
#        return json.loads(response.getvalue())


class MediaObject(ClientObject):

    def _get_url(self, base_path, id, seclevel=None, asnum=None, ip=None, useragent=None, countries=None, referers=None, expires=None, skin=None, drm_token=None, secure=False):
        if type(id) not in (str, unicode):
            raise InvalidParameter('id is not valid')
        base_url = self._client._secure_base_url if secure else self._client._base_url
        url = '%s%s/%s/%s' % (base_url, base_path, self._client._user_id, id)
        url = sign_url(url, self._client._api_key, seclevel=seclevel, asnum=asnum, ip=ip, useragent=useragent, countries=countries, referers=referers, expires=expires) \
            + ('&skin=%s' % skin if skin else '')
        if drm_token:
            drm_token = gen_drm_token(self._client._user_id, id, self._client._api_key,
                                      expires=drm_token.get('expires'),
                                      rights=drm_token.get('rights'),
                                      meta=drm_token.get('meta'),
                                      max_replay=drm_token.get('max_replay'),
                                      callback_url=drm_token.get('callback_url'))
            url += '&drm_token=%s' % drm_token
        return url

    def get_embed_url(self, id, seclevel=None, asnum=None, ip=None, useragent=None, countries=None, referers=None, expires=None, skin=None, drm_token=None, secure=False):
        return self._get_url('/embed', id, seclevel, asnum, ip, useragent, countries, referers, expires, skin, drm_token, secure)

    def get_swf_url(self, id, seclevel=None, asnum=None, ip=None, useragent=None, countries=None, referers=None, expires=None, skin=None, drm_token=None, secure=False):
        return self._get_url('/player/swf', id, seclevel, asnum, ip, useragent, countries, referers, expires, skin, drm_token, secure)

    def get_qtref_url(self, id, seclevel=None, asnum=None, ip=None, useragent=None, countries=None, referers=None, expires=None):
        if type(id) not in (str, unicode):
            raise InvalidParameter('id is not valid')
        url = '%s/stream/%s/%s.mov' % (self._client._base_url, self._client._user_id, id)
        return sign_url(url, self._client._api_key, seclevel=seclevel, asnum=asnum, ip=ip, useragent=useragent, countries=countries, referers=referers, expires=expires)

    def get_stream_url(self, id, asset_name='mp4_h264_aac', seclevel=None, asnum=None, ip=None, useragent=None, countries=None, referers=None, expires=None, download=False, filename=None, version=None, protocol=None, cdn_url='http://cdn.dmcloud.net'):
        if type(id) not in (str, unicode):
            raise InvalidParameter('id is not valid')
        if protocol not in (None, 'hls', 'rtmp', 'hps', 'http', 'ss', 'hds', 'dash'):
            raise InvalidParameter('%s is not a valid streaming protocol' % protocol)
        version = '-%d' % version if version else ''
        if asset_name.startswith('jpeg_thumbnail_'):
            base_url = cdn_url.replace('cdn.', 'static.')
            return '%s/%s/%s/%s%s.jpeg' % (base_url, self._client._user_id, id, asset_name, version)
        extension = '.%s' % asset_name.split('_')[0]
        if download or filename:
            protocol = 'http'

        if asset_name.startswith('abs'):
            extension = ''
            if not protocol:
                raise InvalidParameter('protocol is required for abs asset_name')

        url = '%s/route%s/%s/%s/%s%s%s' % (cdn_url, '/%s' % protocol if protocol else '', self._client._user_id, id, asset_name, version, extension)

        if filename:
            url = '%s?%s' % (url, urllib.urlencode({'filename': filename.encode('utf-8', 'ignore')}))

        return sign_url(url, self._client._api_key, seclevel=seclevel, asnum=asnum, ip=ip, useragent=useragent, countries=countries, referers=referers, expires=expires)


class CloudKey(object):

    def __init__(self, user_id, api_key, base_url='http://api.dmcloud.net', proxy=None, debug=False):
        global _DEBUG
        self._user_id = user_id if user_id else ''
        self._api_key = api_key if api_key else ''
        self._base_url = base_url
        self._secure_base_url = base_url.replace('http:', 'https:')
        self._act_as_user = None
        self._api_endpoint =  base_url + API_ENDPOINT
        self._proxy = proxy
        _DEBUG = debug

    def __getattr__(self, method):
        if method == 'file':
            raise Exception('File methods not implemented (pycurl dependance)')
            #return FileObject(self, method)
        if method == 'media':
            return MediaObject(self, method)
        return ClientObject(self, method)

    def act_as_user(self, user):
        self._act_as_user = user


if __name__ == '__main__':
    import doctest
    doctest.testmod()
