# coding: utf-8
import asyncio
import time

from asynctest import CoroutineMock
from pytest import raises
from sanic import Sanic
from spf import SanicPluginsFramework

from sanic_oauthlib.client import OAuthException, oauthclient
from pytest_sanic.utils import TestClient as SanicTestClient
from .server import create_server, db
from .client import create_client
from .._base import BaseSuite, clean_url
from .._base import to_unicode as u


class OAuthSuite(BaseSuite):
    @property
    def database(self):
        return db

    def create_app(self):
        client_app = Sanic(__name__)
        server_app = Sanic(__name__)
        spf1 = SanicPluginsFramework(client_app)
        spf2 = SanicPluginsFramework(server_app)
        return server_app, client_app

    async def setup_app(self, server_app, client_app):
        self.create_server(server_app)
        loop = asyncio.get_event_loop_policy().get_event_loop()
        self.server_client = SanicTestClient(server_app, loop)
        self.oauth_client = self.create_client(client_app)
        self.oauth_client.http_request = CoroutineMock(
            side_effect=self.patch_request(self.server_client)
        )
        await self.server_client.start_server()
        return server_app

    def create_server(self, app):
        create_server(app)
        return app

    def create_client(self, app):
        return create_client(app)

    async def tearDown(self):
        await self.server_client.close()
        await super(OAuthSuite, self).tearDown()


class TestWebAuth(OAuthSuite):
    async def test_full_flow(self):
        rv = await self.client.get('/login', allow_redirects=False)
        location = rv.headers.get('Location')
        assert 'oauth_token' in location


        auth_url = clean_url(location)
        resp, content = await self.oauth_client.http_request(auth_url)
        assert '</form>' in content

        resp, content = await self.oauth_client.http_request(auth_url, data={
            'confirm': 'yes'
        }, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'oauth_token' in location

        token_url = clean_url(location)
        rv = await self.client.get(token_url)
        content = await rv.text()
        assert 'oauth_token_secret' in content

        rv = await self.client.get('/')
        content = await rv.text()
        assert 'email' in content

        rv = await self.client.get('/address')
        assert rv.status == 401

        rv = await self.client.get('/method/post')
        content = await rv.text()
        assert 'POST' in content

        rv = await self.client.get('/method/put')
        content = await rv.text()
        assert 'PUT' in content

        rv = await self.client.get('/method/delete')
        content = await rv.text()
        assert 'DELETE' in content


    async def test_no_confirm(self):
        rv = await self.client.get('/login', allow_redirects=False)
        location = rv.headers.get('Location')
        assert 'oauth_token' in location

        auth_url = clean_url(location)
        resp, content = await self.oauth_client.http_request(auth_url, data={
            'confirm': 'no'
        }, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'error=denied' in location

    async def test_invalid_request_token(self):
        rv = await self.client.get('/login', allow_redirects=False)
        location = rv.headers.get('Location')
        assert 'oauth_token' in location
        loc = location.replace('oauth_token=', 'oauth_token=a')

        auth_url = clean_url(loc)
        resp, content = await self.oauth_client.http_request(auth_url, allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'error' in location

        resp, content = await self.oauth_client.http_request(auth_url, data={
            'confirm': 'yes'
        }, method='post', allow_redirects=False)
        location = resp.headers.get('Location')
        assert 'error' in location


auth_header = (
    u'OAuth realm="%(realm)s",'
    u'oauth_nonce="97392753692390970531372987366",'
    u'oauth_timestamp="%(timestamp)d", oauth_version="1.0",'
    u'oauth_signature_method="%(signature_method)s",'
    u'oauth_consumer_key="%(key)s",'
    u'oauth_callback="%(callback)s",'
    u'oauth_signature="%(signature)s"'
)
auth_dict = {
    'realm': 'email',
    'timestamp': int(time.time()),
    'key': 'dev',
    'signature_method': 'HMAC-SHA1',
    'callback': 'http%3A%2F%2Flocalhost%2Fauthorized',
    'signature': 'LngsvwVPnd8vCZ2hr7umJvqb%2Fyw%3D',
}


class TestInvalid(OAuthSuite):
    async def test_request(self):
        rv = await self.client.get('/login')
        content = await rv.text()
        assert rv.status == 500
        assert 'error' in content

    async def test_request_token(self):
        rv, content = await self.oauth_client.http_request('/oauth/request_token')
        assert 'error' in content

    async def test_access_token(self):
        rv, content = await self.oauth_client.http_request('/oauth/access_token')
        assert 'error' in content

    async def test_invalid_realms(self):
        auth_format = auth_dict.copy()
        auth_format['realm'] = 'profile'

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv, content = await self.oauth_client.http_request('/oauth/request_token', headers=headers)
        assert 'error' in content
        assert 'realm' in content

    async def test_no_realms(self):
        auth_format = auth_dict.copy()
        auth_format['realm'] = ''

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv, content = await self.oauth_client.http_request('/oauth/request_token', headers=headers)
        assert rv.status == 401

    async def test_no_callback(self):
        auth_format = auth_dict.copy()
        auth_format['callback'] = ''

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv, content = await self.oauth_client.http_request('/oauth/request_token', headers=headers)
        assert 'error' in content
        assert 'callback' in content

    async def test_invalid_signature_method(self):
        auth_format = auth_dict.copy()
        auth_format['signature_method'] = 'PLAIN'

        headers = {
            u'Authorization': auth_header % auth_format
        }
        rv, content = await self.oauth_client.http_request('/oauth/request_token', headers=headers)
        assert 'error' in content
        assert 'signature' in content

    def create_client(self, app):
        spf = SanicPluginsFramework(app)
        oauth = spf.register_plugin(oauthclient)

        remote = oauth.remote_app(
            'dev',
            consumer_key='noclient',
            consumer_secret='dev',
            request_token_params={'realm': 'email'},
            base_url='http://localhost/api/',
            request_token_url='http://localhost/oauth/request_token',
            access_token_method='GET',
            access_token_url='http://localhost/oauth/access_token',
            authorize_url='http://localhost/oauth/authorize'
        )
        return create_client(app, remote)
