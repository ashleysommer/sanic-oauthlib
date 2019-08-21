# coding: utf-8
from sanic import Sanic
from sanic.response import json
from sanic_jinja2_spf import sanic_jinja2
from spf import SanicPluginsFramework
from sanic_oauthlib.provider import oauth1provider
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

db = DB('sqlite:///oauth1.sqlite')

def enable_log(name='sanic_oauthlib'):
    import logging
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)


# enable_log()


class User(db.Base):
    __tablename__ = 'users'
    id = sa.Column(sa.Integer, primary_key=True)
    username = sa.Column(sa.String(40), unique=True, index=True,
                         nullable=False)


class Client(db.Base):
    __tablename__ = 'clients'
    # id = sa.Column(sa.Integer, primary_key=True)
    # human readable name
    client_key = sa.Column(sa.String(40), primary_key=True)
    client_secret = sa.Column(sa.String(55), unique=True, index=True,
                              nullable=False)
    rsa_key = sa.Column(sa.String(55))
    _realms = sa.Column(sa.Text)
    _redirect_uris = sa.Column(sa.Text)

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
    def default_realms(self):
        if self._realms:
            return self._realms.split()
        return []


class Grant(db.Base):
    __tablename__ = 'grants'
    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(
        sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_key = sa.Column(
        sa.String(40), sa.ForeignKey('clients.client_key'),
        nullable=False,
    )
    client = relationship('Client')

    token = sa.Column(sa.String(255), index=True, unique=True)
    secret = sa.Column(sa.String(255), nullable=False)

    verifier = sa.Column(sa.String(255))

    expires = sa.Column(sa.DateTime)
    redirect_uri = sa.Column(sa.Text)
    _realms = sa.Column(sa.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []


class Token(db.Base):
    __tablename__ = 'tokens'
    id = sa.Column(sa.Integer, primary_key=True)
    client_key = sa.Column(
        sa.String(40), sa.ForeignKey('clients.client_key'),
        nullable=False,
    )
    client = relationship('Client')

    user_id = sa.Column(
        sa.Integer, sa.ForeignKey('users.id'),
    )
    user = relationship('User')

    token = sa.Column(sa.String(255))
    secret = sa.Column(sa.String(255))

    _realms = sa.Column(sa.Text)

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []

class Globals(object):
    pass

g = Globals()  # fake globals


def default_provider(app):
    spf = SanicPluginsFramework(app)
    oauth = spf.register_plugin(oauth1provider)

    @oauth.clientgetter
    def get_client(client_key):
        return db.session.query(Client).filter_by(client_key=client_key).first()

    @oauth.tokengetter
    def load_access_token(client_key, token, *args, **kwargs):
        t = db.session.query(Token).filter_by(client_key=client_key, token=token).first()
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
        db.session.add(tok)
        db.session.commit()

    @oauth.grantgetter
    def load_request_token(token):
        grant = db.session.query(Grant).filter_by(token=token).first()
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
        db.session.add(grant)
        db.session.commit()
        return grant

    @oauth.verifiergetter
    def load_verifier(verifier, token):
        return db.session.query(Grant).filter_by(verifier=verifier, token=token).first()

    @oauth.verifiersetter
    def save_verifier(token, verifier, *args, **kwargs):
        tok = db.session.query(Grant).filter_by(token=token).first()
        tok.verifier = verifier['oauth_verifier']
        tok.user_id = g.user.id
        db.session.add(tok)
        db.session.commit()
        return tok

    @oauth.noncegetter
    def load_nonce(*args, **kwargs):
        return None

    @oauth.noncesetter
    def save_nonce(*args, **kwargs):
        return None

    return oauth


def create_server(app):

    app.config.update({
        'OAUTH1_PROVIDER_ENFORCE_SSL': False,
        'OAUTH1_PROVIDER_KEY_LENGTH': (3, 30),
        'OAUTH1_PROVIDER_REALMS': ['email', 'address']
    })
    prepare_app(app)
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

    @app.route('/api/method', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    @oauth.require_oauth()
    def method_api(request, context):
        return json({'method': request.method})

    return app

def prepare_app(app):
    if 'SQLALCHEMY_DATABASE_URI' in app.config:
        db.engine_string = app.config['SQLALCHEMY_DATABASE_URI']
    db.create_all()

    client1 = Client(
        client_key='dev', client_secret='devsecret',
        _redirect_uris=(
            'http://127.0.0.1:5000/authorized '
            'http://127.0.0.1/authorized'
        ),
        _realms='email',
    )

    user = User(username='admin')

    try:
        db.session.add(client1)
        db.session.add(user)
        db.session.commit()
    except:
        db.session.rollback()
    return app


if __name__ == '__main__':
    app = Sanic(__name__)
    spf = SanicPluginsFramework(app)
    app = create_server(app)
    app.run("localhost", 8098, debug=True, auto_reload=False)