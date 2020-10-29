# coding: utf-8

import base64
import os
import tempfile
import asyncio
import pytest
import asynctest

from sanic_oauthlib.client import prepare_request
from pytest_sanic.utils import TestClient as SanicTestClient
from urllib.parse import urlparse

# os.environ['DEBUG'] = 'true'
# for oauthlib 0.6.3

# All test coroutines will be treated as marked.
pytestmark = pytest.mark.asyncio


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'


class BaseSuite(asynctest.TestCase):
    async def setUp(self):
        provider_app, client_app = self.create_app()

        self.db_fd, self.db_file = tempfile.mkstemp()
        provider_config = {
            'SERVER_NAME': '127.0.0.1:5001',
            'OAUTH1_PROVIDER_ENFORCE_SSL': False,
            'OAUTH1_PROVIDER_KEY_LENGTH': (3, 30),
            'OAUTH1_PROVIDER_REALMS': ['email', 'address'],
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///%s' % self.db_file,
            'SQLALCHEMY_TRACK_MODIFICATIONS': False
        }
        provider_app.config.update(provider_config)

        client_config = {
            'SERVER_NAME': '127.0.0.1:5000',
        }
        client_app.config.update(client_config)

        await self.setup_app(provider_app, client_app)

        self.client_app = client_app
        self.provider_app = provider_app
        loop = asyncio.get_event_loop_policy().get_event_loop()
        self.client = SanicTestClient(client_app, loop)
        await self.client.start_server()
        return provider_app

    async def tearDown(self):
        await self.client.close()
        self.database.Session.remove()
        self.database.drop_all()
        os.close(self.db_fd)
        os.unlink(self.db_file)

    @property
    def database(self):
        raise NotImplementedError

    def create_app(self):
        raise NotImplementedError

    def setup_app(self, provider_app, client_app):
        raise NotImplementedError

    def patch_request(self, test_client):
        async def make_request(uri, headers=None, data=None, method=None, **kwargs):
            uri, headers, data, method = prepare_request(
                uri, headers, data, method
            )

            parsed = urlparse(uri)
            uri = '%s?%s' % (parsed.path, parsed.query)
            if not test_client._server.is_running:
                raise RuntimeError("Run TestClient.start_server() first")
            resp = await test_client._request(method,
                uri, headers=headers, data=data, **kwargs)
            content = await resp.text()
            # for compatible
            return resp, content
        return make_request


def to_unicode(text):
    if not isinstance(text, str):
        text = text.decode('utf-8')
    return text


def to_bytes(text):
    if isinstance(text, str):
        text = text.encode('utf-8')
    return text


def to_base64(text):
    return to_unicode(base64.b64encode(to_bytes(text)))


def clean_url(location):
    location = to_unicode(location)
    ret = urlparse(location)
    return '%s?%s' % (ret.path, ret.query)
