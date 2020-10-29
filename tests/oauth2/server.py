# coding: utf-8
import os
from datetime import datetime, timedelta
from sanic import Sanic
from sanic.response import json, HTTPResponse
from sanic_jinja2_spf import sanic_jinja2, FileSystemLoader
from spf import SanicPluginsFramework

from sanic_oauthlib.contrib.oauth2 import bind_sqlalchemy, bind_cache_grant
from sanic_oauthlib.provider import oauth2provider
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, scoped_session


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

db = DB('sqlite:///oauth2.sqlite')

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

class User(db.Base):
    __tablename__ = 'users'
    id = sa.Column(sa.Integer, primary_key=True)
    username = sa.Column(sa.String(40), unique=True, index=True,
                         nullable=False)

    def check_password(self, password):
        return True


class Client(db.Base):
    __tablename__ = 'clients'
    # id = sa.Column(sa.Integer, primary_key=True)
    # human readable name
    name = sa.Column(sa.String(40))
    client_id = sa.Column(sa.String(40), primary_key=True)
    client_secret = sa.Column(sa.String(55), unique=True, index=True,
                              nullable=False)
    client_type = sa.Column(sa.String(20), default='public')
    _redirect_uris = sa.Column(sa.Text)
    default_scope = sa.Column(sa.Text, default='email address')

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
        return ['authorization_code', 'password', 'client_credentials',
                'refresh_token']


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
        expires_in = kwargs.pop('expires_in', None)
        if expires_in is not None:
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
    return oauth

def bind_cache_provider(oauth, app):
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
        tok.user_id = request.user.id
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        # This is optional, if you don't need password credential
        # there is no need to implement this method
        return db.session.query(User).filter_by(username=username).first()

    return oauth

def create_server(app, oauth=None):
    prepare_app(app)
    if oauth is None:
        oauth = default_provider(app)
    spf = SanicPluginsFramework(app)
    here = os.path.dirname(os.path.abspath(__file__))
    loader = FileSystemLoader(os.path.join(here, "templates"))
    jinja2 = spf.register_plugin(sanic_jinja2,
                                 enable_async=True, loader=loader)

    @app.middleware
    def load_current_user(request):
        user = db.session.query(User).get(1)
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

    @app.route('/oauth2/revoke', methods=['POST', 'OPTIONS'])
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

    @app.route('/api/method', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    @oauth.require_oauth()
    def method_api(request, context):
        return json({'method': request.method})

    @oauth.invalid_response
    def require_oauth_invalid(req):
        return json({'message': req.error_message}, 401)

    return app


def prepare_app(app):
    db.create_all()

    client1 = Client(
        name='dev', client_id='dev', client_secret='devsecret',
        _redirect_uris=(
            'http://127.0.0.1:5000/authorized '
            'http://127.0.0.1/authorized'
        ),
    )

    client2 = Client(
        name='confidential', client_id='confidential',
        client_secret='confidential', client_type='confidential',
        _redirect_uris=(
            'http://127.0.0.1:8000/authorized '
            'http://127.0.0.1/authorized'
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

    try:
        db.session.add(client1)
        db.session.add(client2)
        db.session.add(user)
        db.session.add(temp_grant)
        db.session.add(access_token)
        db.session.add(access_token2)
        db.session.commit()
    except:
        db.session.rollback()
    return app

if __name__ == '__main__':
    app = Sanic(__name__)
    spf = SanicPluginsFramework(app)
    app = create_server(app)
    app.run("localhost", 8098, debug=True, auto_reload=False)
