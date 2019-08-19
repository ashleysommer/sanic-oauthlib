# coding: utf-8
from sanic import Sanic
from sanic.response import json
from sanic_jinja2_spf import sanic_jinja2
from spf import SanicPluginsFramework
from sanic_session_spf import session
from sanic_oauthlib.provider import oauth1provider

class MockDBObj(object):

    @classmethod
    def get_autoid(cls):
        autoid = cls.autoid + 1
        cls.autoid = autoid
        return autoid

def enable_log(name='sanic_oauthlib'):
    import logging
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)


# enable_log()

class User(MockDBObj):
    users = {}
    autoid = 0

    @classmethod
    def get_by_id(cls, user_id):
        return cls.users[user_id]

    @classmethod
    def get_by_username(cls, username):
        for u in cls.users.values():
            if u.username == username:
                return u
        raise KeyError(username)

    def __init__(self, **kwargs):
        self.id = None
        self.username = None
        for k, v in kwargs.items():
            setattr(self, k, v)
        if self.id is None:
            self.id = User.get_autoid()
        User.users[self.id] = self



class Client(MockDBObj):
    clients = {}
    autoid = 0

    @classmethod
    def get_by_client_key(cls, client_key):
        for c in cls.clients.values():
            if c.client_key == client_key:
                return c
        raise KeyError(client_key)

    @property
    def user(self):
        return User.get_by_id(1)

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_realms(self):
        if self._realms:
            return self._realms.split()
        return []

    def __init__(self, **kwargs):
        self.id = None
        self.name = None
        self.client_key = None
        self.client_secret = None
        self.rsa_key = None
        self._redirect_uris = None
        self._realms = ""
        for k, v in kwargs.items():
            setattr(self, k, v)
        if self.id is None:
            self.id = Client.get_autoid()
        Client.clients[self.id] = self


class Grant(MockDBObj):
    grants = {}
    autoid = 0

    def __init__(self, **kwargs):
        self.id = None
        self.user_id = None
        self.client_key = None
        self.token = None
        self.secret = None
        self.verifier = None
        self.redirect_uri = None
        self._realms = None
        self.expires = None
        for k, v in kwargs.items():
            setattr(self, k, v)
        if self.id is None:
            self.id = Grant.get_autoid()
        Grant.grants[self.id] = self

    @property
    def user(self):
        if self.user_id is None:
            return None
        return User.get_by_id(self.user_id)

    @property
    def client(self):
        if self.client_key is None:
            return None
        return Client.get_by_client_key(self.client_key)

    @classmethod
    def get_by_id(cls, grant_id):
        return cls.grants[grant_id]

    @classmethod
    def get_by_token(cls, token):
        for g in cls.grants.values():
            if g.token == token:
                return g
        raise KeyError(token)

    @classmethod
    def get_by_verifier(cls, verifier, token):
        for g in cls.grants.values():
            if g.verifier == verifier and g.token == token:
                return g
        raise KeyError((verifier, token))

    def delete(self):
        del Grant.grants[self.id]
        return self

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []


class Token(MockDBObj):
    tokens = {}
    autoid = 0

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []

    def __init__(self, **kwargs):
        self.id = None
        self.user_id = None
        self.client_key = None
        self.token = None
        self.secret = None
        self._realms = None

        for k, v in kwargs.items():
            setattr(self, k, v)
        if self.id is None:
            self.id = Token.get_autoid()
        Token.tokens[self.id] = self

    @property
    def user(self):
        if self.user_id is None:
            return None
        return User.get_by_id(self.user_id)

    @property
    def client(self):
        if self.client_key is None:
            return None
        return Client.get_by_client_key(self.client_key)

    @classmethod
    def get_by_id(cls, token_id):
        return cls.tokens[token_id]

    @classmethod
    def get_by_client_key(cls, client_key, token):
        for t in cls.tokens.values():
            if t.client_key == client_key and t.token == token:
                return t
        raise KeyError((client_key, token))


app = Sanic(__name__)
spf = SanicPluginsFramework(app)

app.config.update({
        'OAUTH1_PROVIDER_ENFORCE_SSL': False,
        'OAUTH1_PROVIDER_KEY_LENGTH': (3, 30),
        'OAUTH1_PROVIDER_REALMS': ['email', 'address']
    })


jinja2 = spf.register_plugin(sanic_jinja2, enable_async=True, pkg_path="../tests/oauth1/templates")
session = spf.register_plugin(session)
oauth = spf.register_plugin(oauth1provider)

class Globals(object):
    pass

g = Globals()  # fake globals


@oauth.clientgetter
def get_client(client_key):
    return Client.get_by_client_key(client_key)

@oauth.tokengetter
def load_access_token(client_key, token, *args, **kwargs):
    t = Token.get_by_client_key(client_key=client_key, token=token)
    return t

@oauth.tokensetter
def save_access_token(token, req):
    tok = Token(
        client_key=req.client.client_key,
        user_id=req.user.id,
        token=token['oauth_token'],
        secret=token['oauth_token_secret'],
        _realms=token['oauth_authorized_realms'],
    )

@oauth.grantgetter
def load_request_token(token):
    grant = Grant.get_by_token(token)
    return grant

@oauth.grantsetter
def save_request_token(token, oauth):
    if oauth.realms:
        realms = ' '.join(oauth.realms)
    else:
        realms = None
    grant = Grant(
        token=token['oauth_token'],
        secret=token['oauth_token_secret'],
        client_key=oauth.client.client_key,
        redirect_uri=oauth.redirect_uri,
        _realms=realms,
    )
    return grant

@oauth.verifiergetter
def load_verifier(verifier, token):
    return Grant.get_by_verifier(verifier=verifier, token=token)

@oauth.verifiersetter
def save_verifier(token, verifier, *args, **kwargs):
    tok = Grant.get_by_token(token)
    tok.verifier = verifier['oauth_verifier']
    tok.user_id = g.user.id
    return tok

@oauth.noncegetter
def load_nonce(*args, **kwargs):
    return None

@oauth.noncesetter
def save_nonce(*args, **kwargs):
    return None

@app.middleware
def load_current_user(request):
    user = User.get_by_id(1)
    g.user = user

@app.route('/home')
async def home(request):
    return await jinja2.render_async('home.html', request, g=g)

@app.route('/oauth/authorize', methods=['GET', 'POST', 'OPTIONS'])
@oauth.authorize_handler
async def authorize(request, *args, context=None, **kwargs):
    # NOTICE: for real project, you need to require login
    if request.method == 'GET':
        # render a page for user to confirm the authorization
        return await jinja2.render_async('confirm.html', request, g=g)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@app.route('/oauth/request_token', methods=['GET', 'POST', 'OPTIONS'])
@oauth.request_token_handler
def request_token(request, context):
    return {}

@app.route('/oauth/access_token', methods=['GET', 'POST', 'OPTIONS'])
@oauth.access_token_handler
def access_token(request, context):
    return {}

@app.route('/api/email')
@oauth.require_oauth('email')
def email_api(request, context):
    request_context = context['request'][id(request)]
    oauth = request_context.oauth
    return json({'email': 'me@oauth.net', 'username': oauth.user.username})

@app.route('/api/user')
@oauth.require_oauth('email')
def user_api(request, context):
    request_context = context['request'][id(request)]
    oauth = request_context.oauth
    return json({'email': 'me@oauth.net', 'username': oauth.user.username, 'id': oauth.user.id, 'verified': True})

@app.route('/api/address/<city>')
@oauth.require_oauth('address')
def address_api(request, city, context):
    request_context = context['request'][id(request)]
    oauth = request_context.oauth
    return json({'address': city, 'username': oauth.user.username})

@app.route('/api/method', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@oauth.require_oauth()
def method_api(request):
    return json({'method': request.method})


def prepare_app(app):
    client1 = Client(
        client_key='dev', client_secret='devsecret',
        _redirect_uris=(
            'http://localhost:8888/oauth '
            'http://127.0.0.1:8888/oauth '
            'http://localhost/oauth'
        ),
        _realms='email',
    )

    user = User(username='admin')

    return app

if __name__ == '__main__':
    app = prepare_app(app)
    app.run("localhost", 8098, debug=True, auto_reload=False)
