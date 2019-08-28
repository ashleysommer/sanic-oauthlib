# coding: utf-8
import os
import unittest
from datetime import datetime, timedelta
from sanic import Sanic
from sanic.response import json, HTTPResponse
from sanic_jinja2_spf import sanic_jinja2
from spf import SanicPluginsFramework

from sanic_oauthlib.contrib.oauth2 import bind_sqlalchemy, bind_cache_grant
from sanic_oauthlib.provider import oauth2provider
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, scoped_session

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

class DB(object):
    def __init__(self, engine_string):
        self.Base = declarative_base()
        self.session_factory = sessionmaker()
        self.Session = scoped_session(self.session_factory)
        self.session = None
        self.engine_string = engine_string
        self.engine = None

    def create_all(self):
        self.engine = sa.create_engine(self.engine_string)
        self.Base.metadata.create_all(self.engine)
        self.session_factory.configure(bind=self.engine)
        self.Session = scoped_session(self.session_factory)
        self.session = self.Session()

    def drop_all(self):
        self.Base.metadata.drop_all(self.engine)

db = DB('sqlite://')

class User(db.Base):
    __tablename__ = 'users'
    id = sa.Column(sa.Integer, primary_key=True)
    username = sa.Column(sa.String(40), unique=True, index=True,
                         nullable=False)

    def check_password(self, password):
        return password != 'wrong'


class Client(db.Base):
    __tablename__ = 'clients'
    # id = sa.Column(sa.Integer, primary_key=True)
    # human readable name
    name = sa.Column(sa.String(40))
    client_id = sa.Column(sa.String(40), primary_key=True)
    client_secret = sa.Column(sa.String(55), unique=True, index=True,
                              nullable=False)
    _redirect_uris = sa.Column(sa.Text)
    default_scope = sa.Column(sa.Text, default='email address')
    disallow_grant_type = sa.Column(sa.String(20))
    is_confidential = sa.Column(sa.Boolean, default=True)

    @property
    def user(self):
        return db.session.query('User').get(1)

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
        types = [
            'authorization_code', 'password',
            'client_credentials', 'refresh_token',
        ]
        if self.disallow_grant_type:
            types.remove(self.disallow_grant_type)
        return types


class Grant(db.Base):
    __tablename__ = 'grants'
    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(
        sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_id = sa.Column(
        sa.String(40), sa.ForeignKey('clients.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
    code = sa.Column(sa.String(255), index=True, nullable=False)

    redirect_uri = sa.Column(sa.String(255))
    scope = sa.Column(sa.Text)
    expires = sa.Column(sa.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return None


class Token(db.Base):
    __tablename__ = 'tokens'
    id = sa.Column(sa.Integer, primary_key=True)
    client_id = sa.Column(
        sa.String(40), sa.ForeignKey('clients.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    user_id = sa.Column(
        sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE')
    )
    user = relationship('User')
    client = relationship('Client')
    token_type = sa.Column(sa.String(40))
    access_token = sa.Column(sa.String(255))
    refresh_token = sa.Column(sa.String(255))
    expires = sa.Column(sa.DateTime)
    scope = sa.Column(sa.Text)

    def __init__(self, **kwargs):
        expires_in = kwargs.pop('expires_in')
        self.expires = datetime.utcnow() + timedelta(seconds=expires_in)
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self



class Globals(object):
    pass

g = Globals()  # fake globals

def current_user():
    return getattr(g, 'user', None)


def cache_provider(app):
    spf = SanicPluginsFramework(app)
    oauth = spf.register_plugin(oauth2provider)
    bind_sqlalchemy(oauth, db.session, user=User,
                    token=Token, client=Client, current_user=current_user)

    app.config.update({'OAUTH2_CACHE_TYPE': 'simple'})
    bind_cache_grant(app, oauth, current_user)
    return oauth


def sqlalchemy_provider(app):
    spf = SanicPluginsFramework(app)
    oauth = spf.register_plugin(oauth2provider)
    bind_sqlalchemy(oauth, db.session, user=User, token=Token,
                    client=Client, grant=Grant, current_user=current_user)

    return oauth


def default_provider(app):
    spf = SanicPluginsFramework(app)
    oauth = spf.register_plugin(oauth2provider)
    @oauth.clientgetter
    def get_client(client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    @oauth.grantgetter
    def get_grant(client_id, code):
        return db.session.query(Grant).filter_by(client_id=client_id, code=code).first()

    @oauth.tokengetter
    def get_token(access_token=None, refresh_token=None):
        if access_token:
            return db.session.query(Token).filter_by(access_token=access_token).first()
        if refresh_token:
            return db.session.query(Token).filter_by(refresh_token=refresh_token).first()
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
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
        # In real project, a token is unique bound to user and client.
        # Which means, you don't need to create a token every time.
        tok = Token(**token)
        if request.response_type == 'token':
            tok.user_id = g.user.id
        else:
            tok.user_id = request.user.id
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        # This is optional, if you don't need password credential
        # there is no need to implement this method
        user = db.session.query(User).filter_by(username=username).first()
        if user and user.check_password(password):
            return user
        return None

    return oauth


def create_server(app, oauth=None):
    if not oauth:
        oauth = default_provider(app)
    spf = SanicPluginsFramework(app)
    jinja2 = spf.register_plugin(sanic_jinja2, enable_async=True)

    @app.middleware
    def load_current_user(request):
        user = db.session.query(User).get(1)
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

        if request.method == 'HEAD':
            # if HEAD is supported properly, request parameters like
            # client_id should be validated the same way as for 'GET'
            response = HTTPResponse('', 200)
            response.headers['X-Client-ID'] = kwargs.get('client_id')
            return response

        confirm = request.form.get('confirm', 'no')
        return confirm == 'yes'

    @app.route('/oauth/token', methods=['POST', 'GET', 'OPTIONS'])
    @oauth.token_handler
    def access_token(request, context):
        return {}

    @app.route('/oauth/revoke', methods=['POST', 'OPTIONS'])
    @oauth.revoke_handler
    def revoke_token(request, context):
        pass

    @app.route('/api/email')
    @oauth.require_oauth('email')
    def email_api(request, context):
        request_context = context['request'][id(request)]
        oauth = request_context.oauth
        return json({'email': 'me@oauth.net', 'username': oauth.user.username})

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

    @app.route('/api/method',
               methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    @oauth.require_oauth()
    def method_api(request, context):
        return json({'method': request.method})

    @oauth.invalid_response
    def require_oauth_invalid(req):
        return json({'message': req.error_message}, 401)

    return app


class TestCase(unittest.TestCase):
    def setUp(self):
        app = self.create_app()

        db.create_all()

        self.app = app
        self.client = app.test_client
        self.prepare_data()

    def tearDown(self):
        db.drop_all()

    def prepare_data(self):
        return True

    def create_app(self):
        app = Sanic(__name__)
        spf = SanicPluginsFramework(app)
        return app
