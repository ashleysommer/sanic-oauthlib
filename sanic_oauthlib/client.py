# coding: utf-8
"""
    sanic_oauthlib.client
    ~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth1 and OAuth2 support for Sanic.

    :copyright: (c) 2013 - 2014 by Hsiaoming Yang.
"""

import logging
from inspect import isawaitable
from asyncio import iscoroutinefunction
import aiohttp
import oauthlib.oauth1
import oauthlib.oauth2
from copy import copy
from functools import wraps, lru_cache
from oauthlib.common import to_unicode, add_params_to_uri, urlencode
from sanic.request import RequestParameters
from sanic.response import redirect, json
from spf import SanicPlugin
from json import loads as json_loads
from json import dumps as json_dumps
from spf.plugin import PluginAssociated

from .utils import to_bytes
from urllib.parse import parse_qs, urljoin, quote, parse_qsl

log = logging.getLogger('sanic_oauthlib')

__all__ = ('OAuthClient', 'OAuthRemoteApp', 'OAuthResponse', 'OAuthException')

class OAuthClientAssociated(PluginAssociated):

    def __new__(cls, oauth_plugin, plugin_reg, **kwargs):
        assert isinstance(oauth_plugin, OAuthClient)
        cached = getattr(cls, 'cached', None)
        if not cached:
            cached = {}
            setattr(cls, 'cached', cached)
        if plugin_reg in cached:
            return cached[plugin_reg]
        self = super(OAuthClientAssociated, cls).\
            __new__(cls, oauth_plugin, plugin_reg, **kwargs)
        cached[plugin_reg] = self
        return self

    @property
    def app(self):
        (_p, reg) = self
        (s, n, _u) = reg
        return s._app

    @property
    def context(self):
        (_p, reg) = self
        (s, n, _u) = reg
        try:
            return s.get_context(n)
        except AttributeError:
            raise RuntimeError("Cannot get context associated with OAuthClient app plugin")

    def remote_app(self, name, register=True, **kwargs):
        """Registers a new remote application.

        :param name: the name of the remote application
        :param register: whether the remote app will be registered

        Find more parameters from :class:`OAuthRemoteApp`.
        """
        remote = OAuthRemoteApp(self, name, **kwargs)
        if register:
            ctx = self.context
            assert name not in ctx.remote_apps
            ctx.remote_apps[name] = remote
        return remote

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            ctx = self.context
            rapp = ctx.remote_apps.get(key)
            if rapp:
                return rapp
            raise AttributeError('No such app: {}'.format(str(key)))


class OAuthClient(SanicPlugin):
    """Registry for remote applications.

    :param app: the app instance of Flask

    Create an instance with Flask::

        oauth = OAuth(app)
    """
    __slots__ = ("_lazy_load_apps",)

    AssociatedTuple = OAuthClientAssociated

    def __init__(self, *args, **kwargs):
        super(OAuthClient, self).__init__(*args, **kwargs)
        self._lazy_load_apps = {}

    def remote_app(self, name, register=True, **kwargs):
        """Registers a new remote application.

        :param name: the name of the remote application
        :param register: whether the remote app will be registered

        Find more parameters from :class:`OAuthRemoteApp`.
        """
        remote = OAuthRemoteApp(None, name, **kwargs)
        if register:
            self._lazy_load_apps[name] = remote
        return remote

    def on_registered(self, context, reg, *args, **kwargs):
        # this will need to be called more than once, for every app it is registered on.
        app = context.app
        context.remote_apps = {}
        assoc = OAuthClientAssociated(self, reg)
        for name, remote in self._lazy_load_apps.items():
            remote.oauth = assoc
            context.remote_apps[name] = remote

        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauthlib.client'] = self


oauthclient = instance = OAuthClient()

_etree = None


def get_etree():
    global _etree
    if _etree is not None:
        return _etree
    try:
        from lxml import etree as _etree
    except ImportError:
        try:
            from xml.etree import cElementTree as _etree
        except ImportError:
            try:
                from xml.etree import ElementTree as _etree
            except ImportError:
                raise TypeError('lxml or etree not found')
    return _etree


def parse_options_header(ct):
    ct_parts = str(ct).split(";", 1)
    ct = ct_parts[0]
    ct = ct.strip()
    extra = ct_parts[1] if len(ct_parts) > 1 else ""
    extra = extra.strip()
    options = {}
    if len(extra) < 1:
        return ct, options
    extra_chunks = extra.split(";")
    extra_chunks2 = []
    _ = [extra_chunks2.extend(e.split(",")) for e in extra_chunks]
    extra_chunks3 = []
    _ = [extra_chunks3.extend(e.split(" ")) for e in extra_chunks2]

    for e in extra_chunks3:
        if "=" not in e:
            continue
        k, v = e.split("=", 1)
        options[k.strip()] = v.strip()
    return ct, options

def parse_response(resp, content, strict=False, content_type=None):
    """Parse the response returned by :meth:`OAuthRemoteApp.http_request`.

    :param resp: response of http_request
    :param content: content of the response
    :param strict: strict mode for form urlencoded content
    :param content_type: assign a content type manually
    """
    if not content_type:
        content_type = resp.headers.get('content-type', 'application/json')
    ct, options = parse_options_header(content_type)

    if ct in ('application/json', 'text/javascript'):
        if not content:
            return {}
        return json_loads(content)

    if ct in ('application/xml', 'text/xml'):
        return get_etree().fromstring(content)

    if ct != 'application/x-www-form-urlencoded' and strict:
        return content
    charset = options.get('charset', 'utf-8')
    return RequestParameters(parse_qs(content, encoding=charset))


def prepare_request(uri, headers=None, data=None, method=None):
    """Make request parameters right."""
    if headers is None:
        headers = {}

    if data and not method:
        method = 'POST'
    elif not method:
        method = 'GET'

    if method == 'GET' and data:
        uri = add_params_to_uri(uri, data)
        data = None

    return uri, headers, data, method


def encode_request_data(data, format):
    if format is None:
        return data, None
    if format == 'json':
        return json_dumps(data or {}), 'application/json'
    if format == 'urlencoded':
        return urlencode(data or {}), 'application/x-www-form-urlencoded'
    raise TypeError('Unknown format %r' % format)


class OAuthResponse(object):
    def __init__(self, resp, content, content_type=None):
        self._resp = resp
        self.raw_data = content
        self.data = parse_response(
            resp, content, strict=True,
            content_type=content_type,
        )

    @property
    def status(self):
        """The status code of the response."""
        return self._resp.status


class OAuthException(RuntimeError):
    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        return self.message

    def __unicode__(self):
        return self.message


class OAuthRemoteApp(object):
    """Represents a remote application.

    :param oauth: the associated :class:`OAuth` object
    :param name: the name of the remote application
    :param base_url: the base url for every request
    :param request_token_url: the url for requesting new tokens
    :param access_token_url: the url for token exchange
    :param authorize_url: the url for authorization
    :param consumer_key: the application specific consumer key
    :param consumer_secret: the application specific consumer secret
    :param request_token_params: an optional dictionary of parameters
                                 to forward to the request token url
                                 or authorize url depending on oauth
                                 version
    :param request_token_method: the HTTP method that should be used for
                                 the access_token_url. Default is ``GET``
    :param access_token_params: an optional dictionary of parameters to
                                forward to the access token url
    :param access_token_method: the HTTP method that should be used for
                                the access_token_url. Default is ``GET``
    :param access_token_headers: additonal headers that should be used for
                                 the access_token_url.
    :param content_type: force to parse the content with this content_type,
                         usually used when the server didn't return the
                         right content type.

    .. versionadded:: 0.3.0

    :param app_key: lazy load configuration from Flask app config with
                    this app key
    """
    def __init__(
        self, oauth, name,
        base_url=None,
        request_token_url=None,
        access_token_url=None,
        authorize_url=None,
        consumer_key=None,
        consumer_secret=None,
        rsa_key=None,
        signature_method=None,
        request_token_params=None,
        request_token_method=None,
        access_token_params=None,
        access_token_method=None,
        access_token_headers=None,
        content_type=None,
        app_key=None,
        encoding='utf-8',
    ):
        self.oauth = oauth
        self.name = name

        self._base_url = base_url
        self._request_token_url = request_token_url
        self._access_token_url = access_token_url
        self._authorize_url = authorize_url
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self._rsa_key = rsa_key
        self._signature_method = signature_method
        self._request_token_params = request_token_params
        self._request_token_method = request_token_method
        self._access_token_params = access_token_params
        self._access_token_method = access_token_method
        self._access_token_headers = access_token_headers or {}
        self._content_type = content_type
        self._tokengetter = None

        self.app_key = app_key
        self.encoding = encoding

        # Check for required authentication information.
        # Skip this check if app_key is specified, since the information is
        # specified in the Flask config, instead.
        if not app_key:
            if signature_method == oauthlib.oauth1.SIGNATURE_RSA:
                # check for consumer_key and rsa_key
                if not consumer_key or not rsa_key:
                    raise TypeError(
                        "OAuthRemoteApp with RSA authentication requires "
                        "consumer key and rsa key"
                    )
            else:
                # check for consumer_key and consumer_secret
                if not consumer_key or not consumer_secret:
                    raise TypeError(
                        "OAuthRemoteApp requires consumer key and secret"
                    )

    @property
    @lru_cache()
    def base_url(self):
        return self._get_property('base_url')

    @property
    @lru_cache()
    def request_token_url(self):
        return self._get_property('request_token_url', None)

    @property
    @lru_cache()
    def access_token_url(self):
        return self._get_property('access_token_url')

    @property
    @lru_cache()
    def authorize_url(self):
        return self._get_property('authorize_url')

    @property
    @lru_cache()
    def consumer_key(self):
        return self._get_property('consumer_key')

    @property
    @lru_cache()
    def consumer_secret(self):
        return self._get_property('consumer_secret')

    @property
    @lru_cache()
    def rsa_key(self):
        return self._get_property('rsa_key')

    @property
    @lru_cache()
    def signature_method(self):
        return self._get_property('signature_method')

    @property
    @lru_cache()
    def request_token_params(self):
        return self._get_property('request_token_params', {})

    @property
    @lru_cache()
    def request_token_method(self):
        return self._get_property('request_token_method', 'GET')

    @property
    @lru_cache()
    def access_token_params(self):
        return self._get_property('access_token_params', {})

    @property
    @lru_cache()
    def access_token_method(self):
        return self._get_property('access_token_method', 'POST')

    @property
    @lru_cache()
    def content_type(self):
        return self._get_property('content_type', None)

    def _get_property(self, key, default=False):
        attr = getattr(self, '_%s' % key)
        if attr is not None:
            return attr
        if not self.app_key:
            if default is not False:
                return default
            return attr
        app = self.oauth.app
        if self.app_key in app.config:
            # works with dict config
            config = app.config[self.app_key]
            if default is not False:
                return config.get(key, default)
            return config[key]
        # works with plain text config
        config_key = "%s_%s" % (self.app_key, key.upper())
        if default is not False:
            return app.config.get(config_key, default)
        return app.config[config_key]

    def get_oauth1_client_params(self, token):
        params = copy(self.request_token_params) or {}
        if token and isinstance(token, (tuple, list)):
            params["resource_owner_key"] = token[0]
            params["resource_owner_secret"] = token[1]

        # Set params for SIGNATURE_RSA
        if self.signature_method == oauthlib.oauth1.SIGNATURE_RSA:
            params["signature_method"] = self.signature_method
            params["rsa_key"] = self.rsa_key

        return params

    def make_client(self, token=None):
        # request_token_url is for oauth1
        if self.request_token_url:
            # get params for client
            params = self.get_oauth1_client_params(token)
            client = oauthlib.oauth1.Client(
                client_key=self.consumer_key,
                client_secret=self.consumer_secret,
                **params
            )
        else:
            if token:
                if isinstance(token, (tuple, list)):
                    token = {'access_token': token[0]}
                elif isinstance(token, str):
                    token = {'access_token': token}
            client = oauthlib.oauth2.WebApplicationClient(
                self.consumer_key, token=token
            )
        return client

    @staticmethod
    async def http_request(uri, headers=None, data=None, method=None):
        uri, headers, data, method = prepare_request(
            uri, headers, data, method
        )

        log.debug('Request %r with %r method' % (uri, method))
        http_session = aiohttp.ClientSession()
        resp = await http_session._request(method, uri, headers=headers, data=data)
        content = await resp.text()
        return resp, content

    async def get(self, *args, **kwargs):
        """Sends a ``GET`` request. Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'GET'
        return await self.request(*args, **kwargs)

    async def post(self, *args, **kwargs):
        """Sends a ``POST`` request. Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'POST'
        return await self.request(*args, **kwargs)

    async def put(self, *args, **kwargs):
        """Sends a ``PUT`` request. Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'PUT'
        return await self.request(*args, **kwargs)

    async def delete(self, *args, **kwargs):
        """Sends a ``DELETE`` request. Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'DELETE'
        return await self.request(*args, **kwargs)

    async def patch(self, *args, **kwargs):
        """Sends a ``PATCH`` request. Accepts the same parameters as
        :meth:`post`.
        """
        kwargs['method'] = 'PATCH'
        return await self.request(*args, **kwargs)

    async def request(self, url, data=None, headers=None, format='urlencoded',
                method='GET', content_type=None, token=None):
        """
        Sends a request to the remote server with OAuth tokens attached.

        :param data: the data to be sent to the server.
        :param headers: an optional dictionary of headers.
        :param format: the format for the `data`. Can be `urlencoded` for
                       URL encoded data or `json` for JSON.
        :param method: the HTTP request method to use.
        :param content_type: an optional content type. If a content type
                             is provided, the data is passed as it, and
                             the `format` is ignored.
        :param token: an optional token to pass, if it is None, token will
                      be generated by tokengetter.
        """

        headers = dict(headers or {})
        if token is None:
            token = await self.get_request_token()

        client = self.make_client(token)
        url = self.expand_url(url)
        if method == 'GET':
            assert format == 'urlencoded'
            if data:
                url = add_params_to_uri(url, data)
                data = None
        else:
            if content_type is None:
                data, content_type = encode_request_data(data, format)
            if content_type is not None:
                headers['Content-Type'] = content_type

        if self.request_token_url:
            # oauth1
            uri, headers, body = client.sign(
                url, http_method=method, body=data, headers=headers
            )
        else:
            # oauth2
            uri, headers, body = client.add_token(
                url, http_method=method, body=data, headers=headers
            )

        if hasattr(self, 'pre_request'):
            # This is designed for some rubbish services like weibo.
            # Since they don't follow the standards, we need to
            # change the uri, headers, or body.
            uri, headers, body = self.pre_request(uri, headers, body)

        if body:
            data = to_bytes(body, self.encoding)
        else:
            data = None
        resp, content = await self.http_request(
            uri, headers, data=to_bytes(body, self.encoding), method=method
        )
        return OAuthResponse(resp, content, self.content_type)

    async def authorize(self, request, session, callback=None, state=None, **kwargs):
        """
        Returns a redirect response to the remote authorization URL with
        the signed callback given.

        :param session: the current request session dict
        :param callback: a redirect url for the callback
        :param state: an optional value to embed in the OAuth request.
                      Use this if you want to pass around application
                      state (e.g. CSRF tokens).
        :param kwargs: add optional key/value pairs to the query string
        """
        params = dict(self.request_token_params) or {}
        params.update(**kwargs)

        if self.request_token_url:  # Here we must be OAuth1
            token = (await self.generate_request_token(request, session, callback))[0]
            url = '%s?oauth_token=%s' % (
                self.expand_url(self.authorize_url), quote(token)
            )
            if params:
                tuple_list = [(k,v) for k,v in params.items()]
                url += '&' + urlencode(tuple_list)
        else:
            assert callback is not None, 'Callback is required for OAuth2'

            client = self.make_client()

            if 'scope' in params:
                scope = params.pop('scope')
            else:
                scope = None

            if isinstance(scope, str):
                # oauthlib need unicode
                scope = _encode(scope, self.encoding)

            if 'state' in params:
                if not state:
                    state = params.pop('state')
                else:
                    # remove state in params
                    params.pop('state')

            if callable(state):
                # state can be function for generate a random string
                state = state()

            session['%s_oauthredir' % self.name] = callback
            url = client.prepare_request_uri(
                self.expand_url(self.authorize_url),
                redirect_uri=callback,
                scope=scope,
                state=state,
                **params
            )
        return redirect(url)

    def autoauthorize(self, f):
        context = self.oauth.context
        is_coro = iscoroutinefunction(f)
        @wraps(f)
        async def wrapper(request, *args, **kwargs):
            nonlocal self, f, context, is_coro
            shared_request = context.shared.request[id(request)]
            session = getattr(shared_request, 'session', {})
            if is_coro:
                auth_args = await f(request, context, *args, **kwargs)
            else:
                auth_args = f(request, context, *args, **kwargs)
            if isawaitable(auth_args):
                auth_args = await auth_args
            return await self.authorize(request, session, **auth_args)
        return wrapper

    def tokengetter(self, f):
        """
        Register a function as token getter.
        """
        self._tokengetter = f
        return f

    def expand_url(self, url):
        return urljoin(self.base_url, url)

    async def generate_request_token(self, request, session, callback=None):
        # for oauth1 only
        if callback is not None:
            callback = urljoin(request.url, callback)

        client = self.make_client()
        client.callback_uri = _encode(callback, self.encoding)

        realm = self.request_token_params.get('realm')
        realms = self.request_token_params.get('realms')
        if not realm and realms:
            realm = ' '.join(realms)
        uri, headers, _ = client.sign(
            self.expand_url(self.request_token_url),
            http_method=self.request_token_method,
            realm=realm,
        )
        log.debug('Generate request token header %r', headers)
        resp, content = await self.http_request(
            uri, headers, method=self.request_token_method,
        )
        data = parse_response(resp, content)
        if not data:
            raise OAuthException(
                'Invalid token response from %s' % self.name,
                type='token_generation_failed'
            )
        if resp.status not in (200, 201):
            message = 'Failed to generate request token'
            if 'oauth_problem' in data:
                message += ' (%s)' % data['oauth_problem']
            raise OAuthException(
                message,
                type='token_generation_failed',
                data=data,
            )
        tup = (data.get('oauth_token'), data.get('oauth_token_secret'))
        session['%s_oauthtok' % self.name] = tup
        return tup

    async def get_request_token(self):
        assert self._tokengetter is not None, 'missing tokengetter'
        if iscoroutinefunction(self._tokengetter):
            rv = await self._tokengetter()
        else:
            rv = self._tokengetter()
        if isawaitable(rv):
            rv = await rv
        if rv is None:
            raise OAuthException('No token available', type='token_missing')
        return rv

    async def handle_oauth1_response(self, session, args):
        """Handles an oauth1 authorization response."""
        client = self.make_client()
        client.verifier = args.get('oauth_verifier')
        tup = session.get('%s_oauthtok' % self.name)
        if not tup:
            raise OAuthException(
                'Token not found, maybe you disabled cookie',
                type='token_not_found'
            )
        client.resource_owner_key = tup[0]
        client.resource_owner_secret = tup[1]

        uri, headers, data = client.sign(
            self.expand_url(self.access_token_url),
            _encode(self.access_token_method)
        )
        headers.update(self._access_token_headers)

        resp, content = await self.http_request(
            uri, headers, to_bytes(data, self.encoding),
            method=self.access_token_method
        )
        data = parse_response(resp, content)
        if resp.status not in (200, 201):
            raise OAuthException(
                'Invalid response from %s' % self.name,
                type='invalid_response', data=data
            )
        return data

    async def handle_oauth2_response(self, session, args):
        """Handles an oauth2 authorization response."""

        client = self.make_client()
        remote_args = {
            'code': args.get('code'),
            'client_secret': self.consumer_secret,
            'redirect_uri': session.get('%s_oauthredir' % self.name)
        }
        log.debug('Prepare oauth2 remote args %r', remote_args)
        remote_args.update(self.access_token_params)
        headers = copy(self._access_token_headers)
        if self.access_token_method == 'POST':
            headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
            body = client.prepare_request_body(**remote_args)
            resp, content = await self.http_request(
                self.expand_url(self.access_token_url),
                headers=headers,
                data=to_bytes(body, self.encoding),
                method=self.access_token_method,
            )
        elif self.access_token_method == 'GET':
            qs = client.prepare_request_body(**remote_args)
            url = self.expand_url(self.access_token_url)
            url += ('?' in url and '&' or '?') + qs
            resp, content = await self.http_request(
                url,
                headers=headers,
                method=self.access_token_method,
            )
        else:
            raise OAuthException(
                'Unsupported access_token_method: %s' %
                self.access_token_method
            )

        data = parse_response(resp, content, content_type=self.content_type)
        if resp.status not in (200, 201):
            raise OAuthException(
                'Invalid response from %s' % self.name,
                type='invalid_response', data=data
            )
        return data

    def handle_unknown_response(self):
        """Handles a unknown authorization response."""
        return None

    async def authorized_response(self, request, session, args=None):
        """Handles authorization response smartly."""
        if args is None:
            args = request.args
        if 'oauth_verifier' in args:
            data = await self.handle_oauth1_response(session, args)
        elif 'code' in args:
            data = await self.handle_oauth2_response(session, args)
        else:
            data = self.handle_unknown_response()

        # free request token
        session.pop('%s_oauthtok' % self.name, None)
        session.pop('%s_oauthredir' % self.name, None)
        return data

    def authorized_handler(self, f):
        """Handles an OAuth callback."""
        context = self.oauth.context
        is_coro = iscoroutinefunction(f)
        @wraps(f)
        async def decorated(request, *args, **kwargs):
            nonlocal self, f, context, is_coro
            shared_request = context.shared.request[id(request)]
            session = getattr(shared_request, 'session', {})
            data = await self.authorized_response(request, session)
            if is_coro:
                res = await f(request, data, context, *args, **kwargs)
            else:
                res = f(request, data, context, *args, **kwargs)
            if isawaitable(res):
                res = await res
            return res
        return decorated


def _encode(text, encoding='utf-8'):
    if encoding:
        return to_unicode(text, encoding)
    return text
