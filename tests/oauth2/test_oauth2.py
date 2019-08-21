# coding: utf-8
import asyncio
import json

from asynctest import CoroutineMock
from sanic import Sanic
from pytest_sanic.utils import TestClient as SanicTestClient
from spf import SanicPluginsFramework

from .server import (
    create_server,
    db,
    cache_provider,
    sqlalchemy_provider,
    default_provider,
    Token
)
from .client import create_client
from .._base import BaseSuite, clean_url, to_base64
from .._base import to_unicode as u


class OAuthSuite(BaseSuite):
    @property
    def database(self):
        return db

    def create_oauth_provider(app):
        raise NotImplementedError('Each test class must'
                                  'implement this method.')

    def create_app(self):
        client_app = Sanic(__name__)
        server_app = Sanic(__name__)
        spf1 = SanicPluginsFramework(client_app)
        spf2 = SanicPluginsFramework(server_app)
        return server_app, client_app

    async def setup_app(self, server_app, client_app):
        oauth = self.create_oauth_provider(server_app)
        loop = asyncio.get_event_loop_policy().get_event_loop()
        self.server_client = SanicTestClient(server_app, loop)
        create_server(server_app, oauth)
        self.oauth_client = create_client(client_app)
        self.oauth_client.http_request = CoroutineMock(
            side_effect=self.patch_request(self.server_client)
        )
        await self.server_client.start_server()
        return server_app

    async def tearDown(self):
        await self.server_client.close()
        await super(OAuthSuite, self).tearDown()


authorize_url = (
    '/oauth2/authorize?response_type=code&client_id=dev'
    '&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fauthorized&scope=email'
)


auth_code = to_base64('confidential:confidential')


class TestWebAuth(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    async def test_login(self):
        rv = await self.client.get('/login', allow_redirects=False)
        location = rv.headers.get('Location')
        assert 'response_type=code' in location

    async def test_oauth_authorize_invalid_url(self):
        resp, content = await self.oauth_client.http_request('/oauth2/authorize', allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'Missing+client_id+parameter.' in location

    async def test_oauth_authorize_valid_url(self):
        resp, content = await self.oauth_client.http_request(authorize_url)
        assert '</form>' in content

        resp, content = await self.oauth_client.http_request(authorize_url, data=dict(
            confirm='no'
        ), method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'access_denied' in location

        resp, content = await self.oauth_client.http_request(authorize_url, data=dict(
            confirm='yes'
        ), method='post', allow_redirects=False)
        # success
        location = resp.headers.get('Location')
        assert 'code=' in location
        assert 'state' not in location

        # test state on access denied
        # According to RFC 6749, state should be preserved on error response if it's present in the client request.
        # Reference: https://tools.ietf.org/html/rfc6749#section-4.1.2
        resp, content = await self.oauth_client.http_request(authorize_url + '&state=foo', data=dict(
            confirm='no'
        ), method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'error=access_denied' in location
        assert 'state=foo' in location

        # test state on success
        resp, content = await self.oauth_client.http_request(authorize_url + '&state=foo', data=dict(
            confirm='yes'
        ), method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'code=' in location
        assert 'state=foo' in location

    async def test_http_head_oauth_authorize_valid_url(self):
        resp, content = await self.oauth_client.http_request(authorize_url, method='head', allow_redirects=False)
        assert resp.headers['X-Client-ID'] == 'dev'

    async def test_get_access_token(self):
        resp, content = await self.oauth_client.http_request(authorize_url,
            data={'confirm': 'yes'}, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        rv = await self.client.get(clean_url(location))
        await rv.read()
        assert b'access_token' in rv._body

    async def test_full_flow(self):
        resp, content = await self.oauth_client.http_request(authorize_url,
            data={'confirm': 'yes'}, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        rv = await self.client.get(clean_url(location))
        await rv.read()
        assert b'access_token' in rv._body

        rv = await self.client.get('/')
        await rv.read()
        assert b'username' in rv._body

        rv = await self.client.get('/address')
        assert rv.status == 401
        await rv.read()
        assert b'message' in rv._body

        rv = await self.client.get('/method/post')
        await rv.read()
        assert b'POST' in rv._body

        rv = await self.client.get('/method/put')
        await rv.read()
        assert b'PUT' in rv._body

        rv = await self.client.get('/method/delete')
        await rv.read()
        assert b'DELETE' in rv._body

    async def test_no_bear_token(self):
        @self.oauth_client.tokengetter
        def get_oauth_token():
            return 'foo', ''

        rv = await self.client.get('/method/put')
        _ = await rv.read()
        assert b'token not found' in rv._body

    async def test_expires_bear_token(self):
        @self.oauth_client.tokengetter
        def get_oauth_token():
            return 'expired', ''

        rv = await self.client.get('/method/put')
        _ = await rv.read()
        assert b'token is expired' in rv._body

    async def test_never_expiring_bear_token(self):
        @self.oauth_client.tokengetter
        def get_oauth_token():
            return 'never_expire', ''

        rv = await self.client.get('/method/put')
        assert rv.status == 200

    async def test_get_client(self):
        resp, content = await self.oauth_client.http_request(authorize_url,
            data={'confirm': 'yes'}, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        rv = await self.client.get(clean_url(location))
        await rv.read()
        rv = await self.client.get("/client")
        await rv.read()
        assert b'dev' in rv._body

    async def test_invalid_response_type(self):
        authorize_url = (
            '/oauth2/authorize?response_type=invalid&client_id=dev'
            '&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fauthorized'
            '&scope=email'
        )
        resp, content = await self.oauth_client.http_request(authorize_url,
            data={'confirm': 'yes'}, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        rv = await self.client.get(clean_url(location))
        await rv.read()
        assert b'error' in rv._body

    async def test_invalid_scope(self):
        authorize_url = (
            '/oauth2/authorize?response_type=code&client_id=dev'
            '&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fauthorized'
            '&scope=invalid'
        )
        resp, content = await self.oauth_client.http_request(authorize_url,
            data={'confirm': 'yes'}, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        rv = await self.client.get(clean_url(location))
        await rv.read()
        assert b'error' in rv._body
        assert b'invalid_scope' in rv._body


class TestWebAuthCached(TestWebAuth):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestWebAuthSQLAlchemy(TestWebAuth):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestRefreshToken(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def test_refresh_token_in_password_grant(self):
        url = ('/oauth/token?grant_type=password'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'access_token' in rv.data
        data = json.loads(u(rv.data))

        args = (data.get('scope').replace(' ', '+'),
                data.get('refresh_token'))
        url = ('/oauth/token?grant_type=refresh_token'
               '&scope=%s&refresh_token=%s')
        url = url % args
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'access_token' in rv.data

    def test_refresh_token_in_authorization_code(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(location))
        data = json.loads(u(rv.data))

        args = (data.get('scope').replace(' ', '+'),
                data.get('refresh_token'), 'dev', 'dev')
        url = ('/oauth/token?grant_type=refresh_token'
               '&scope=%s&refresh_token=%s'
               '&client_id=%s&client_secret=%s')
        url = url % args
        rv = self.client.get(url)
        assert b'access_token' in rv.data


class TestRefreshTokenCached(TestRefreshToken):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestRefreshTokenSQLAlchemy(TestRefreshToken):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestRevokeToken(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def get_token(self):
        url = ('/oauth/token?grant_type=password'
               '&scope=email+address&username=admin&password=admin')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'_token' in rv.data
        return json.loads(u(rv.data))

    def test_revoke_token(self):
        data = self.get_token()
        tok = Token.query.filter_by(
            refresh_token=data['refresh_token']).first()
        assert tok.refresh_token == data['refresh_token']

        revoke_url = '/oauth/revoke'
        args = {'token': data['refresh_token']}
        self.client.post(revoke_url, data=args, headers={
            'Authorization': 'Basic %s' % auth_code,
        })

        tok = Token.query.filter_by(
            refresh_token=data['refresh_token']).first()
        assert tok is None

    def test_revoke_token_with_hint(self):
        data = self.get_token()
        tok = Token.query.filter_by(
            access_token=data['access_token']).first()
        assert tok.access_token == data['access_token']

        revoke_url = '/oauth/revoke'
        args = {'token': data['access_token'],
                'token_type_hint': 'access_token'}
        self.client.post(revoke_url, data=args, headers={
            'Authorization': 'Basic %s' % auth_code,
        })

        tok = Token.query.filter_by(
            access_token=data['access_token']).first()
        assert tok is None


class TestRevokeTokenCached(TestRefreshToken):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestRevokeTokenSQLAlchemy(TestRefreshToken):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestCredentialAuth(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def test_get_access_token(self):
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'access_token' in rv.data

    def test_invalid_auth_header(self):
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic foobar'
        })
        assert b'invalid_client' in rv.data

    def test_no_client(self):
        auth_code = to_base64('none:confidential')
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'invalid_client' in rv.data

    def test_wrong_secret_client(self):
        auth_code = to_base64('confidential:wrong')
        url = ('/oauth/token?grant_type=client_credentials'
               '&scope=email+address')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert b'invalid_client' in rv.data


class TestCredentialAuthCached(TestCredentialAuth):

    def create_oauth_provider(self, app):
        return cache_provider(app)


class TestCredentialAuthSQLAlchemy(TestCredentialAuth):

    def create_oauth_provider(self, app):
        return sqlalchemy_provider(app)


class TestTokenGenerator(OAuthSuite):

    def create_oauth_provider(self, app):

        def generator(request):
            return 'foobar'

        app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = generator
        return default_provider(app)

    def test_get_access_token(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(location))
        data = json.loads(u(rv.data))
        assert data['access_token'] == 'foobar'
        assert data['refresh_token'] == 'foobar'


class TestRefreshTokenGenerator(OAuthSuite):

    def create_oauth_provider(self, app):

        def at_generator(request):
            return 'foobar'

        def rt_generator(request):
            return 'abracadabra'

        app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = at_generator
        app.config['OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR'] = rt_generator
        return default_provider(app)

    def test_get_access_token(self):
        rv = self.client.post(authorize_url, data={'confirm': 'yes'})
        rv = self.client.get(clean_url(location))
        data = json.loads(u(rv.data))
        assert data['access_token'] == 'foobar'
        assert data['refresh_token'] == 'abracadabra'


class TestConfidentialClient(OAuthSuite):

    def create_oauth_provider(self, app):
        return default_provider(app)

    def test_get_access_token(self):
        url = ('/oauth/token?grant_type=authorization_code&code=12345'
               '&scope=email')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code
        })
        assert b'access_token' in rv.data

    def test_invalid_grant(self):
        url = ('/oauth/token?grant_type=authorization_code&code=54321'
               '&scope=email')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % auth_code
        })
        assert b'invalid_grant' in rv.data

    def test_invalid_client(self):
        url = ('/oauth/token?grant_type=authorization_code&code=12345'
               '&scope=email')
        rv = self.client.get(url, headers={
            'Authorization': 'Basic %s' % ('foo')
        })
        assert b'invalid_client' in rv.data
