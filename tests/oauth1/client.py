from inspect import isawaitable
from sanic import Sanic
from sanic.response import redirect, json, text
from sanic.exceptions import SanicException
from spf import SanicPluginsFramework
from sanic_oauthlib.client import oauthclient


def create_oauth(app):
    spf = SanicPluginsFramework(app)
    try:
        oauth = spf.register_plugin(oauthclient)
    except ValueError as v:
        _, oauth = v
    return oauth


def create_remote(app, oauth=None):
    if not oauth:
        oauth = create_oauth(app)

    remote = oauth.remote_app(
        'dev',
        consumer_key='dev',
        consumer_secret='devsecret',
        request_token_params={'realm': 'email'},
        base_url='http://127.0.0.1:5001/api/',
        request_token_url='http://127.0.0.1:5001/oauth/request_token',
        access_token_method='GET',
        access_token_url='http://127.0.0.1:5001/oauth/access_token',
        authorize_url='http://127.0.0.1:5001/oauth/authorize'
    )
    return remote


def create_client(app, oauth=None, remote=None):

    if not oauth:
        oauth = create_oauth(app)

    if not remote:
        remote = create_remote(app, oauth)

    session = {}
    #TODO: make a better client session for test

    @app.middleware
    async def add_dummy_session(request):
        context = oauth.context
        shared_context = oauth.context.shared
        shared_request_context = shared_context.request[id(request)]
        shared_request_context['session'] = session

    @app.route('/')
    async def index(request):
        if 'dev_oauth' in session:
            ret = await remote.get('email')
            if isinstance(ret.data, dict):
                return json(ret.data)
            return str(ret.data)
        return redirect(app.url_for('login'))

    @app.route('/login')
    @remote.autoauthorize
    async def login(request, context):
        return {'callback': app.url_for('authorized', _external=True, _scheme='http')}

    @app.route('/logout')
    def logout(request):
        session.pop('dev_oauth', None)
        return redirect(app.url_for('index'))

    @app.route('/authorized')
    @remote.authorized_handler
    async def authorized(request, data, context):
        if data is None:
            return 'Access denied: error=%s' % (
                request.args['error']
            )
        resp = {k: v[0] for k, v in data.items()}
        if 'oauth_token' in resp:
            session['dev_oauth'] = resp
            return json(resp)
        return text(str(resp))

    @app.route('/address')
    async def address(request):
        ret = await remote.get('address/hangzhou')
        if ret.status not in (200, 201):
            raise SanicException(ret.data, status_code=ret.status)
        return text(ret.raw_data)

    @app.route('/method/<name>')
    async def method(request, name):
        func = getattr(remote, name)
        ret = func('method')
        if isawaitable(ret):
            ret = await ret
        return text(ret.raw_data)

    @remote.tokengetter
    def get_oauth_token():
        if 'dev_oauth' in session:
            resp = session['dev_oauth']
            return resp['oauth_token'], resp['oauth_token_secret']

    return remote


if __name__ == '__main__':
    app = Sanic(__name__)
    create_client(app)
    app.run(host='localhost', port=8000, debug=True, auto_reload=False)
