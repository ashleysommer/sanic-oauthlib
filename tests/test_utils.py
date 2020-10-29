import unittest
from contextlib import contextmanager
import mock
from sanic_oauthlib.utils import extract_params
from sanic.request import Request as SanicRequest
from oauthlib.common import Request
from sanic.server import serve, HttpProtocol
from inspect import isawaitable
from sanic.app import Sanic
from sanic.compat import Header
import socket
import asyncio
from aiohttp import ClientSession, CookieJar

REQUEST_DEFAULTS = {
    "METHOD": b"GET",
    "VERSION": b"1.1",
    "SCHEME": b"http",
    "HOST": b"127.0.0.1",
    "PORT": 80,
    "PATH": b"/",
    "QUERY_STRING": b"",
}

class DummyTransport(object):
    def __init__(self, is_ssl=False):
        self.is_ssl = is_ssl

    def get_extra_info(self, info):
        if info == "sslcontext":
            return self.is_ssl
        raise NotImplementedError(info)

@contextmanager
def set_request(wsgi_environ, app=None, transport=None):
    """
    Test helper context manager that mocks the sanic request
    """
    environ = {}
    headers = Header()
    environ.update(wsgi_environ)
    for k, v in REQUEST_DEFAULTS.items():
        environ.setdefault(k, v)
    url_bytes = b"%s://%s" % (environ['SCHEME'], environ['HOST'])
    headers.setdefault('Host', environ['HOST'].decode('utf-8'))
    if environ['SCHEME'] == b"http" and environ['PORT'] in (80, b"80"):
        pass
    elif environ['SCHEME'] == b"https" and environ['PORT'] in (443, b"443"):
        pass
    else:
        port = environ['PORT']
        if isinstance(port, int):
            port = str(port)
        if isinstance(port, str):
            port = port.encode('latin-1')

        url_bytes = b"%s:%s" % (url_bytes, port)
    if environ['PATH'] == b"":
        pass
    else:
        path = environ['PATH']
        if path == b"/":
            path = b""
        url_bytes = b"%s/%s" % (url_bytes, path)
    if environ['QUERY_STRING'] == b"":
        pass
    else:
        url_bytes = b"%s?%s" % (url_bytes, environ['QUERY_STRING'])
    version = environ['VERSION'].decode('utf-8')
    method = environ['METHOD'].decode('utf-8')
    if app is None:
        app = set_request.app
    if transport is None:
        transport = DummyTransport()
    r = SanicRequest(url_bytes, headers, version, method, transport, app)

    with mock.patch.dict(extract_params.__globals__, {'request': r}):
        yield
set_request.app = Sanic(__name__)

class UtilsTestSuite(unittest.TestCase):

    def test_extract_params(self):
        with set_request({'QUERY_STRING': b'test=foo&foo=bar'}):
            uri, http_method, body, headers = extract_params()
            self.assertEquals(uri, 'http://127.0.0.1/?test=foo&foo=bar')
            self.assertEquals(http_method, 'GET')
            self.assertEquals(body, {})
            self.assertEquals(headers, Header({'Host': '127.0.0.1'}))

    def test_extract_params_with_urlencoded_json(self):
        wsgi_environ = {
            'QUERY_STRING': b'state=%7B%22t%22%3A%22a%22%2C%22i%22%3A%22l%22%7D'
        }
        with set_request(wsgi_environ):
            uri, http_method, body, headers = extract_params()
            # Request constructor will try to urldecode the querystring, make
            # sure this doesn't fail.
            Request(uri, http_method, body, headers)
