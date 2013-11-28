#!/usr/bin/env python
# vim: set fileencoding=utf-8 :
'''Module to measure the reception ratio of a rtmp video hosted on DM Cloud
'''

from __future__ import print_function

VERSION = '1.1'

import argparse
import sys
import os
import logging
import urllib2
from urllib import urlencode
import urlparse
from bs4 import BeautifulSoup
import cookielib
import re
import time
import sqlite3
import getpass

from cloudkey_nocurl import CloudKey

import rtmplite.rtmpclient
import rtmplite.multitask
from rtmplite.rtmp import Command
MESSAGE_RPC = 0x14
import socket

DATABASE_CONNECTION = None
DATABASE_CURSOR = None

DURATION = 60
TIMEOUT = 10

NB_USERS = 1

RTMP_PORT = 1935
RTMP_PING_SIZE = 1536

API_KEY = None
OUTPUT_FILE = None

MATCHER_LIVE_URL = (r'^(\w*)(://cdn.dmcloud.net/route/)(\w*/)(\w{24})/(\w{24})/'
                r'(live_1.m3u8\?auth=)(\d{10})-(\d)-(\w{8})-(\w{32})(?:-\w*)?$')

VIDEOMDP_NAME = 'videoMdp'
VIDEO_SCREEN_ID = 'video_screen'
STATIC_SWF_URL = ('https://api.dmcloud.net/static/_5a8c258f_/dmplayer/'
                  'dmplayer.swf?withLoader=1')

MOZILLA_HEADERS = ('User-agent', 'Mozilla/5.0')

# for interactive call: do not add multiple times the handler
if 'LOG' not in locals():
    LOG = None
LOG_LEVEL = logging.ERROR
FORMATER_STRING = ('%(asctime)s - %(filename)s:%(lineno)d - '
                   '%(levelname)s - %(message)s')

def configure_log(level=LOG_LEVEL, log_file=None):
    'Configure logger'
    if LOG:
        LOG.setLevel(level)
        return LOG
    log = logging.getLogger('%s log' % os.path.basename(__file__))
    if log_file:
        handler = logging.FileHandler(filename=log_file)
    else:
        handler = logging.StreamHandler(sys.stderr)
    log_formatter = logging.Formatter(FORMATER_STRING)
    handler.setFormatter(log_formatter)
    log.addHandler(handler)
    log.setLevel(level)
    return log

LOG = configure_log()

class PasswordException(Exception):
    '''Exception when password not set for the page'''
    pass

def set_cookie(opener, passwd_form, url, password=None):
    '''Submit password to retrieve cookie, and set it in the url opener'''
    LOG.debug('Need to enter password')
    values = {}
    for tag in passwd_form.contents:
        if tag == '\n':
            continue
        attrs = tag.attrs
        if 'value' in attrs and 'name' in attrs:
            values[attrs['name']] = attrs['value']
            if attrs['name'] == VIDEOMDP_NAME:
                if not password:
                    password = getpass.getpass('Please enter your password:\n')
                    #raise PasswordException, 'Password needed and not set'
                values[VIDEOMDP_NAME] = password
    data = urlencode(values)
    data = data.encode('utf-8')
    # as passwd_form.attrs['action'] is an absolute path, it replaces the whole
    # path of url
    form_url = urlparse.urljoin(url, passwd_form.attrs['action'])
    LOG.debug('Password form_url: %s', form_url)
    cookie_jar = cookielib.CookieJar()
    opener.add_handler(urllib2.HTTPCookieProcessor(cookie_jar))
    opener.open(form_url, data)

def store_page(soup, url, ext=''):
    '''Store the contents of the page in a file (named according to url)'''
    parsed_url = urlparse.urlparse(url)
    url_file_name = parsed_url.path.split('/')[-1] + ext
    LOG.info('Storing url %s in file %s', url, url_file_name)
    with open(url_file_name, 'w') as url_file:
        #for line in soup.contents:
        url_file.write(soup.prettify().encode('utf8'))

def my_connect(self, url, timeout=None, my_parse=True, *args):
    # Generator to connect to the given url, and return True or False.
    '''Change of the connect method to handle generic cases'''
    if url[:7].lower() != 'rtmp://':
        raise ValueError, 'Invalid URL scheme. Must be rtmp://'
    if my_parse:
        parsed_url = urlparse.urlparse(url)
        host = parsed_url.netloc.split(':')[0]
        port = RTMP_PORT
        path = urlparse.ParseResult(scheme='', netloc='', path=parsed_url.path,
                                    query=parsed_url.query, params='',
                                    fragment='').geturl().lstrip('/')
    else:
        path, ignore, ignore = url[7:].partition('?')
        hostport, ignore, path = path.partition('/')
        host, port = (hostport.split(':', 1) + ['1935'])[:2]
    self.data.tcUrl, self.data.app = url, path
    sock = socket.socket(type=socket.SOCK_STREAM)
    LOG.debug(' '.join(map(str, ('NetConnection.connect url=', url, 'host=',
                                 host, 'port=', port))))
    try:
        sock.connect((host, int(port)))
    except:
        raise StopIteration, False
    # make it non-block
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    self.client = yield rtmplite.rtmpclient.Client(sock).handshake()
    result, fault = yield self.client.send(
                        Command(name='connect', cmdData=self.data, args=args),
                                            timeout=timeout)
    LOG.debug(' '.join(map(str, ('NetConnection.connect result=', result,
                                 'fault=', fault))))
    raise StopIteration, (result is not None)

rtmplite.rtmpclient.NetConnection.connect = my_connect

def measure(rtmp_url):
    '''Modified version of the rtmpclient.connect function'''
    net_connection = yield rtmplite.rtmpclient.NetConnection()
    net_connection.data = rtmplite.rtmpclient.Object(
                                                    flashVer='LNX 11,9,900,152',
                                                    swfUrl=STATIC_SWF_URL,
                                                    fpad=False,
                                                    capabilities=239.0,
                                                    audioCodecs=3575.0,
                                                    videoCodecs=252.0,
                                                    videoFunction=1.0,
                                                    pageUrl=None,
                                                    objectEncoding=3.0)
    parsed_url = urlparse.urlparse(rtmp_url)
    new_url = urlparse.ParseResult(scheme=parsed_url.scheme,
                                netloc=':'.join((parsed_url.netloc, '1935')),
                                            path=parsed_url.path.split('/')[1],
                                            query=parsed_url.query,
                                            params='',
                                            fragment='')
    result = yield net_connection.connect(new_url.geturl(), TIMEOUT)
    net_stream = yield rtmplite.rtmpclient.NetStream().create(net_connection,
                                                              timeout=TIMEOUT)
    if not net_stream:
        LOG.debug('Failed to create stream')
        raise StopIteration, 'Failed to create stream'
    play_id = '?'.join((parsed_url.path.split('/live-dc/')[1],
                        parsed_url.query))
    result = yield net_stream.play(play_id, timeout=TIMEOUT)
    if not result:
        LOG.debug('Failed to play stream %r', play_id)
        yield net_connection.close()
        raise StopIteration, 'Failed to play stream %r' % play_id
    # if the remote side terminates before duration,
    LOG.info('starting playback for duration: %d', DURATION)
    start = time.time()
    try:
        yield net_connection.client.close_queue.get(timeout=DURATION)
        LOG.debug('received connection close')
    except (rtmplite.multitask.Timeout, GeneratorExit):
        # else wait until duration
        LOG.info('duration completed, connect closing')
        yield net_connection.close()
    finally:
        end = time.time()
        LOG.debug('start, end, duration: (%s, %s, %s)', start, end, end - start)
        put_result_db(rtmp_url, start, end, end - start)

def web_scrap(url, store, password=None, ext=''):
    '''Parse the front-end page to get to video'''
    LOG.info('Start working with url: %s', url)
    opener = urllib2.build_opener()
    opener.addheaders = [MOZILLA_HEADERS]
    embedding_page = yield opener.open(url)
    soup = BeautifulSoup(embedding_page)
    passwd_form = soup.find('form', 'videoPassword')
    if passwd_form:
        set_cookie(opener, passwd_form, url, password=password)
        embedding_page = yield opener.open(url)
        soup = BeautifulSoup(embedding_page)
    if store:
        store_page(soup, url, ext)
    video_screen = soup.find('div', {'id': VIDEO_SCREEN_ID})
    if not video_screen:
        LOG.critical('no video_screen found')
        raise StopIteration, 'no video_screen found'
    iframe = video_screen.find('iframe')
    if not iframe:
        LOG.critical('no iframe found')
        raise StopIteration, 'no iframe found'
    try:
        video_api_url = iframe.attrs['src']
    except AttributeError, mes:
        LOG.exception(mes)
        raise StopIteration, 'no video_api_url found'
    LOG.debug('video_api_url: %s', video_api_url)
    video_api_page = yield opener.open(video_api_url)
    soup = BeautifulSoup(video_api_page)
    if store:
        store_page(soup, video_api_url, ext)
    for cur_script in soup('script'):
        if 'ios_url' in cur_script.text:
            script = cur_script
            break
    # for else
    else:
        LOG.critical('no video_script found')
        raise StopIteration, 'no video_script found'
    live_url_match = re.search(r'"ios_url": "(.*?)", ', script.text)
    if not live_url_match:
        LOG.critical('no live_url_match found')
        raise StopIteration, 'no live_url_match found'
    live_url_groups = live_url_match.groups()
    if len(live_url_groups) != 1:
        raise StopIteration, 'ambiguity on the live url'
    LOG.debug('live_url_groups: %s' % live_url_groups)
    yield retrieve_rtmp(live_url_groups[0], store, ext)

def retrieve_rtmp(live_url, store, ext=''):
    '''Retrieve the rtmp url'''
    LOG.debug('Start working with live_url: %s' % live_url)
    match = re.match(MATCHER_LIVE_URL, live_url)
    if not match:
        LOG.critical('no match on this url: %s', live_url)
        raise StopIteration, 'no match on this url: %s' % live_url
    (protocol, base, asset_name, user_id, media_id, m3u8_file,
                     expires, sec_level, nonce, md5sum) = match.groups()
    LOG.debug('user_id: %s', user_id)
    LOG.debug('media_id: %s', media_id)
    try:
        cloudkey = CloudKey(user_id, API_KEY)
        video_asset = yield cloudkey.media.get_assets(id=media_id)
    except Exception, mes:
        LOG.exception(mes)
        LOG.critical('could not access the media through cloudkey')
        raise StopIteration, 'could not access the media through cloudkey'
    if not video_asset:
        LOG.critical('no asset found for media: %s', media_id)
        raise StopIteration, 'no asset found for media: %s' % media_id
    try:
        stream_url = video_asset['live_1']['stream_url']
    except AttributeError, mes:
        LOG.exception(mes)
        LOG.critical('could not find stream_url')
        raise StopIteration, 'could not find stream_url'
    LOG.debug('found stream url: %s', stream_url)
    stream_page = yield urllib2.urlopen(stream_url)
    soup = BeautifulSoup(stream_page)
    if store:
        store_page(soup, stream_url, ext)
    try:
        rtmp_url = soup.getText()
    except AttributeError, mes:
        LOG.exception(mes)
        LOG.critical('could not find rtmp_url')
        raise StopIteration, 'could not find rtmp_url'
    LOG.info('rtmp_url: %s', rtmp_url)
    yield measure(rtmp_url)

def create_db():
    '''Set the database for the results'''
    global DATABASE_CONNECTION, DATABASE_CURSOR
    DATABASE_CONNECTION = sqlite3.connect(':memory:')
    DATABASE_CURSOR = DATABASE_CONNECTION.cursor()
    DATABASE_CURSOR.execute('''CREATE TABLE results (url, start, end, duration)''')

def put_result_db(*results):
    '''Put the result in database'''
    DATABASE_CURSOR.execute('''INSERT INTO results VALUES (?, ?, ?, ?)''',
                            results)

def output_db_results():
    '''Print the results from the database'''
    DATABASE_CONNECTION.commit()
    with open(OUTPUT_FILE, 'w') as output_file:
        for row in DATABASE_CURSOR.execute('''SELECT * FROM results'''):
            print(row, file=output_file)
    DATABASE_CONNECTION.close()

#def process_url(url, store, password, ext):
#    '''Complete processing of front end url up to rtmp measurement'''
#    live_url = web_scrap(url, store, password, ext)
#    rtmp_url = retrieve_rtmp(live_url, store, ext)
#    measure(rtmp_url)

def launch_measure(url, store, nb_users=NB_USERS, password=None):
    '''Put the measure function in the multitask queue'''
    create_db()
    LOG.info('launching %d users' % nb_users)
    for index in range(nb_users):
        rtmplite.multitask.add(web_scrap(url, store, password,
                                           ext=('_%d' % index)))
    try:
        rtmplite.multitask.run()
    except rtmplite.rtmpclient.Result, msg:
        print('result', msg)
    except KeyboardInterrupt:
        print('keyboard interrupt')
    finally:
        output_db_results()
    return 0

def main(argv=None):
    'Program wrapper'
    if argv is None:
        argv = sys.argv[1:]
    global DURATION, TIMEOUT, API_KEY, OUTPUT_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--debug', dest='debug', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-s', '--store', dest='store',
                        action='store_true', default=False,
                        help='store intermediate web pages (default False)')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-q', '--quiet', dest='quiet',
                        action='store_true', default=False,
                        help='run as quiet mode')
    group.add_argument('-v', '--verbose', dest='verbose',
                        action='store_true', default=False,
                        help='run as verbose mode')
    parser.add_argument('-a', '--api-key', dest='api_key', required=True,
                        help='API KEY to retrieve the content')
    parser.add_argument('-d', '--duration', dest='duration',
                        type=int, default=DURATION,
                        help=('set duration of download in seconds (default %d)'
                              % DURATION))
    parser.add_argument('-t', '--timeout', dest='timeout',
                        type=int, default=TIMEOUT,
                        help=('set duration of timeout for connections '
                              '(default %d)' % TIMEOUT))
    parser.add_argument('-p', '--password', dest='password', default='',
                       help='Password for the video (if needed)')
    parser.add_argument('-n', '--nb_users', dest='nb_users',
                        type=int, default=NB_USERS,
                        help=('Number of users to simulate (default %d)'
                              % NB_USERS))
    parser.add_argument('-o', '--output-file', dest='output_file',
                        default=None, help='output file (default stdout)')
    parser.add_argument('url', help='url of the embedding page')
    args = parser.parse_args(argv)
    if args.quiet and args.verbose:
        parser.error('Options quiet and verbose are mutually exclusive')
    if args.verbose:
        LOG.setLevel(logging.INFO)
    if args.quiet:
        LOG.setLevel(logging.CRITICAL)
    if args.debug:
        LOG.setLevel(logging.DEBUG)
        rtmplite.rtmpclient._debug = True
    if args.output_file:
        try:
            with open(args.output_file, 'w') as _:
                OUTPUT_FILE = args.output_file
        except IOError, mes:
            LOG.exception(mes)
            LOG.error('Cannot open file %s for writing output',
                      args.output_file)
            args.output_file = None
            LOG.error('Using stdout for output')
            OUTPUT_FILE = '/dev/stdout'
    else:
        OUTPUT_FILE = '/dev/stdout'
    API_KEY = args.api_key
    DURATION = args.duration
    TIMEOUT = args.timeout
    ret_code = launch_measure(args.url, args.store, nb_users=args.nb_users,
                              password=args.password)
    return ret_code

if __name__ == '__main__':
    import doctest
    doctest.testmod()
    sys.exit(main())

