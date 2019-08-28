from inspect import isawaitable

from sanic import Sanic
from sanic.response import redirect, json, text
from sanic.exceptions import SanicException
from spf import SanicPluginsFramework
from sanic_oauthlib.client import oauthclient

def create_client(app):
    spf = SanicPluginsFramework(app)
    oauth = spf.register_plugin(oauthclient)

    session = {}
    #TODO: make a better client session for tests

    remote = oauth.remote_app(
        'dev',
        consumer_key='dev',
        consumer_secret='devsecret',
        request_token_params={'scope': 'email'},
        base_url='http://127.0.0.1:5001/api/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='http://127.0.0.1:5001/oauth2/token',
        authorize_url='http://127.0.0.1:5001/oauth2/authorize'
    )

    @app.middleware
    async def add_dummy_session(request):
        context = oauth.context
        shared_context = oauth.context.shared
        shared_request_context = shared_context.request[id(request)]
        shared_request_context['session'] = session


    @app.route('/')
    async def index(request):
        if 'dev_token' in session:
            ret = await remote.get('email')
            return json(ret.data)
        return redirect(app.url_for('login'))

    @app.route('/login')
    @remote.autoauthorize
    async def login(request, context):
        return {'callback': app.url_for('authorized', _external=True, _scheme='http')}

    @app.route('/logout')
    def logout(request):
        session.pop('dev_token', None)
        return redirect(app.url_for('index'))

    @app.route('/authorized')
    @remote.authorized_handler
    async def authorized(request, data, context):
        if data is None:
            return text('Access denied: error=%s' % (
                request.args['error']
            ))
        #Oauth2 response is JSON
        if 'access_token' in data:
            session['dev_token'] = (data['access_token'], '')
            return json(data)
        return text(str(data))

    @app.route('/client')
    async def client_method(request):
        ret = await remote.get("client")
        if ret.status not in (200, 201):
            raise SanicException(ret.data, status_code=ret.status)
        return text(ret.raw_data)

    @app.route('/address')
    async def address(request):
        ret = await remote.get('address/hangzhou')
        if ret.status not in (200, 201):
            raise SanicException(ret.raw_data, status_code=ret.status)
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
        return session.get('dev_token')

    return remote


if __name__ == '__main__':
    import os
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    app = Sanic(__name__)
    create_client(app)
    app.run(host='localhost', port=8000, debug=True, auto_reload=False)
