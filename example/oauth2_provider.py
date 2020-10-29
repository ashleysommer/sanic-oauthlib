# coding: utf-8
import os
from datetime import datetime, timedelta
from sanic import Sanic
from sanic.response import HTTPResponse, json
from spf import SanicPluginsFramework
from sanic_jinja2_spf import sanic_jinja2, FileSystemLoader
from sanic_session_spf import session
from sanic_oauthlib.provider import oauth2provider


class MockDBObj(object):

    @classmethod
    def get_autoid(cls):
        autoid = cls.autoid + 1
        cls.autoid = autoid
        return autoid

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

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

    def check_password(self, password):
        return True


class Client(MockDBObj):
    clients = {}
    autoid = 0

    @classmethod
    def get_by_client_id(cls, client_id):
        for c in cls.clients.values():
            if c.client_id == client_id:
                return c
        raise KeyError(client_id)

    def __init__(self, **kwargs):
        self.id = None
        self.name = None
        self.client_id = None
        self.client_secret = None
        self.client_type = 'public'
        self._redirect_uris = None
        self.default_scope = 'email address'
        self.pkce_required = True
        for k, v in kwargs.items():
            setattr(self, k, v)
        if self.id is None:
            self.id = Client.get_autoid()
        Client.clients[self.id] = self

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
    def default_scopes(self):
        if self.default_scope:
            return self.default_scope.split()
        return []

    @property
    def allowed_grant_types(self):
        return ['authorization_code', 'password', 'client_credentials',
                'refresh_token']


class Grant(MockDBObj):
    grants = {}
    autoid = 0

    def __init__(self, **kwargs):
        self.id = None
        self.user_id = None
        self.client_id = None
        self.code = None
        self.redirect_uri = None
        self.scope = None
        self.nonce = None
        self.code_challenge = None
        self.code_challenge_method = None
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
        if self.client_id is None:
            return None
        return Client.get_by_client_id(self.client_id)

    @classmethod
    def get_by_id(cls, grant_id):
        return cls.grants[grant_id]

    @classmethod
    def get_by_client_id(cls, client_id, code):
        for g in cls.grants.values():
            if g.client_id == client_id and g.code == code:
                return g
        raise KeyError(client_id)

    def delete(self):
        del Grant.grants[self.id]
        return self

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return None


class Token(MockDBObj):
    tokens = {}
    autoid = 0

    def __init__(self, **kwargs):
        self.id = None
        self.user_id = None
        self.client_id = None
        self.token_type = None
        self.access_token = None
        self.refresh_token = None
        self.scope = None
        expires_in = kwargs.pop('expires_in', None)
        if expires_in is not None:
            self.expires = datetime.utcnow() + timedelta(seconds=expires_in)

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
        if self.client_id is None:
            return None
        return Client.get_by_client_id(self.client_id)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []

    @classmethod
    def get_by_id(cls, token_id):
        return cls.tokens[token_id]

    @classmethod
    def get_by_client_id(cls, client_id):
        for t in cls.tokens.values():
            if t.client_id == client_id:
                return t
        raise KeyError(client_id)

    @classmethod
    def get_by_access_token(cls, access_token):
        for t in cls.tokens.values():
            if t.access_token == access_token:
                return t
        raise KeyError(access_token)

    @classmethod
    def get_by_refresh_token(cls, refresh_token):
        for t in cls.tokens.values():
            if t.refresh_token == refresh_token:
                return t
        raise KeyError(refresh_token)

    def delete(self):
        del Token.tokens[self.id]
        return self

# def current_user():
#     return g.user


# def cache_provider(app):
#     oauth = OAuth2Provider(app)
#
#     bind_sqlalchemy(oauth, db.session, user=User,
#                     token=Token, client=Client)
#
#     app.config.update({'OAUTH2_CACHE_TYPE': 'simple'})
#     bind_cache_grant(app, oauth, current_user)
#     return oauth
#
#
# def sqlalchemy_provider(app):
#     oauth = OAuth2Provider(app)
#
#     bind_sqlalchemy(oauth, db.session, user=User, token=Token,
#                     client=Client, grant=Grant, current_user=current_user)
#
#     return oauth

app = Sanic(__name__)
spf = SanicPluginsFramework(app)
loader = FileSystemLoader("../tests/oauth2/templates")
jinja2 = spf.register_plugin(sanic_jinja2, enable_async=True, loader=loader)
session = spf.register_plugin(session)
oauth = spf.register_plugin(oauth2provider)
class Globals(object):
    pass

g = Globals()  # fake globals


@oauth.clientgetter
def get_client(client_id):
    return Client.get_by_client_id(client_id)

@oauth.grantgetter
def get_grant(client_id, code):
    return Grant.get_by_client_id(client_id, code)

@oauth.tokengetter
def get_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.get_by_access_token(access_token)
    if refresh_token:
        return Token.get_by_refresh_token(refresh_token)
    return None

@oauth.grantsetter
def set_grant(client_id, code, request, *args, **kwargs):
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        scope=' '.join(request.scopes),
        user_id=g.user.id,
        nonce=code.get('nonce', None),
        code_challenge=getattr(request, 'code_challenge', None),
        code_challenge_method=getattr(request, 'code_challenge_method', None),
        expires=expires,
    )

@oauth.tokensetter
def set_token(token, request, *args, **kwargs):
    # In real project, a token is unique bound to user and client.
    # Which means, you don't need to create a token every time.
    tok = Token(**token)
    tok.user_id = request.user.id
    tok.client_id = request.client.client_id

@oauth.usergetter
def get_user(username, password, *args, **kwargs):
    # This is optional, if you don't need password credential
    # there is no need to implement this method
    return User.get_by_username(username)

@app.middleware
def load_current_user(request):
    user = User.get_by_id(1)
    g.user = user

@app.route('/home')
async def home(request):
    return await jinja2.render_async('home.html', request, g=g)

@app.route('/oauth2/authorize', methods=['GET', 'POST', 'HEAD', 'OPTIONS'])
@oauth.authorize_handler
async def authorize(request, *args, context=None, **kwargs):
    # NOTICE: for real project, you need to require login
    if request.method == 'GET':
        # render a page for user to confirm the authorization
        return await jinja2.render_async('confirm.html', request, g=g)

    if request.method == 'HEAD':
        # if HEAD is supported properly, request parameters like
        # client_id should be validated the same way as for 'GET'
        response = HTTPResponse('', 200)
        response.headers['X-Client-ID'] = kwargs.get('client_id')
        return response

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@app.route('/oauth2/token', methods=['POST', 'OPTIONS'])
@oauth.token_handler
def access_token(request, context):
    return {}

@app.route('/oauth2/revoke', methods=['POST', ['OPTIONS']])
@oauth.revoke_handler
def revoke_token(_request):
    pass

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

@app.route('/api/client')
@oauth.require_oauth()
def client_api(request, context):
    request_context = context['request'][id(request)]
    oauth = request_context.oauth
    return json({'client': oauth.client.name})

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

@oauth.invalid_response
def require_oauth_invalid(req):
    return json({'message': req.error_message}, 401)

@app.middleware('response')
def add_cors(request, response):
    response.headers['Access-Control-Allow-Origin'] = "*"

def prepare_app(app):

    client1 = Client(
        name='dev', client_id='dev', client_secret='devsecret',
        _redirect_uris=(
            'http://localhost:8888/oauth '
            'http://127.0.0.1:8888/oauth '
            'http://localhost/oauth'
        ),
    )

    client2 = Client(
        name='confidential', client_id='confidential',
        client_secret='confidential', client_type='confidential',
        _redirect_uris=(
            'http://localhost:8000/authorized '
            'http://localhost/authorized'
        ),
    )

    user = User(username='admin')

    temp_grant = Grant(
        user_id=1, client_id='confidential',
        code='12345', scope='email',
        expires=datetime.utcnow() + timedelta(seconds=100)
    )

    access_token = Token(
        user_id=1, client_id='dev', access_token='expired', expires_in=0
    )

    access_token2 = Token(
        user_id=1, client_id='dev', access_token='never_expire'
    )
    return app


if __name__ == "__main__":
    app = prepare_app(app)
    app.run("localhost", 8098, debug=True, auto_reload=False)
