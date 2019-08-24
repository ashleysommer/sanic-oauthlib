# coding: utf-8

import base64
import importlib
from sanic.response import HTTPResponse
from oauthlib.common import to_unicode, bytes_type


def _get_uri_from_request(request):
    """
    The uri returned from request.uri is not properly urlencoded
    (sometimes it's partially urldecoded) This is a weird hack to get
    werkzeug to return the proper urlencoded string uri
    """
    uri = request._parsed_url.path
    if request._parsed_url.query:
        uri = uri+b'?'+request._parsed_url.query
    try:
        server_name = request.server_name
    except AttributeError:
        server_name = request.host
    port_included = True
    if ":" in server_name:
        server_name, port = server_name.split(':', 1)
    else:
        try:
            port = request.server_port
            assert port is not None
            assert port > 0
        except Exception:
            port = 80
        if request.scheme == "https" and port == 443:
            port_included = False
        elif request.scheme == "http" and port == 80:
            port_included = False

    if port_included:
        return request.scheme + "://" + server_name + ':' + str(port) + uri.decode('utf-8')
    return request.scheme + "://" + server_name + uri.decode('utf-8')



def extract_params(request=None):
    """Extract request params."""
    if request is None:
        if 'request' in extract_params.__globals__:
            request = extract_params.__globals__['request']
        else:
            raise ValueError('request')
    uri = _get_uri_from_request(request)
    http_method = request.method
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']

    body = {k:request.form.get(k) for k in request.form.keys()}
    return uri, http_method, body, headers


def to_bytes(text, encoding='utf-8'):
    """Make sure text is bytes type."""
    if not text:
        return text
    if not isinstance(text, bytes_type):
        text = text.encode(encoding)
    return text


def decode_base64(text, encoding='utf-8'):
    """Decode base64 string."""
    text = to_bytes(text, encoding)
    return to_unicode(base64.b64decode(text), encoding)


def create_response(headers, body, status):
    """Create response class for Sanic."""
    response = HTTPResponse(body, status)
    for k, v in headers.items():
        response.headers[str(k)] = v
    return response


def import_string(name, silent=False):
    """
    Imports an object based on a string. This is useful if you want to use import paths as endpoints or something similar. An import path can be specified either in dotted notation (xml.sax.saxutils.escape) or with a colon as object delimiter (xml.sax.saxutils:escape).
    If silent is True the return value will be None if the import fails.
    :param name:
    :type name: str
    :param silent:
    :type silent: bool
    :return:
    """
    attr_stack = []
    if ":" in name:
        name, obj = name.rsplit(':', 1)
        attr_stack.append(obj)
    try:
        mod = importlib.import_module(name)
        if attr_stack:
            try:
                return getattr(mod, attr_stack[0])
            except AttributeError:
                raise ImportError()
    except ImportError as e:
        while "." in name:
            name, ext = name.rsplit('.', 1)
            attr_stack.append(ext)
            try:
                mod = importlib.import_module(name)
            except ImportError as e2:
                e = e2
                continue
            a = mod
            for i in reversed(attr_stack):
                try:
                    a = getattr(a, i)
                except AttributeError:
                    raise ImportError()
            return a

        if silent:
            return None
        raise e

