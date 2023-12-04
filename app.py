from flask import Flask, request, redirect, session, render_template
from dotenv import load_dotenv
import duo_universal, os, json, requests

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

##########################################
############## Duo Web SDK ###############
##########################################

sdk_client_id = os.getenv("SDK_CLIENT_ID")
sdk_client_secret = os.getenv("SDK_CLIENT_SECRET")
sdk_api_host = os.getenv("SDK_API_HOST")
sdk_redirect_uri = os.getenv("SDK_REDIRECT_URI")
duo_client = duo_universal.Client(sdk_client_id, sdk_client_secret, sdk_api_host, sdk_redirect_uri)

@app.post('/websdk')
def post_websdk():
    try:
        duo_client.health_check()
    except DuoException:
        abort(500)
    state = duo_client.generate_state()
    session['state'] = state
    session['username'] = request.form.get('username')
    prompt_uri = duo_client.create_auth_url(request.form.get('username'), state)
    return redirect(prompt_uri)

@app.get('/websdk/callback')
def get_websdk_callback():
    state = request.args.get('state')
    code = request.args.get('duo_code')
    if state != session.get('state'):
        abort(403)
    try:
        decoded_token = duo_client.exchange_authorization_code_for_2fa_result(code, session.get('username'))
        session['method'] = "Duo Web SDK"
        session['duo_session'] = decoded_token['auth_context']['txid']
    except DuoException as e:
        abort(401)
    return redirect('/home')

@app.post('/websdk/logout')
def post_websdk_logout():
    session['method'] = None
    session['state'] = None
    session['duo_session'] = None
    session['username'] = None
    return redirect('/login')

##########################################
############## Duo SAML SSO ##############
##########################################

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml')

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth

def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'script_name': request.path,
        'get_data': request.args.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.form.copy()
    }

@app.post('/saml/sso')
def post_saml_sso():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login(return_to='/home'))

@app.post('/saml/acs')
def post_saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if len(errors) == 0:
        session['method'] = "Duo SSO with SAML 2.0"
        session['username'] = auth.get_nameid()
        session['duo_session'] = auth.get_session_index()
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlNameIdFormat'] = auth.get_nameid_format()
        session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
        session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
        session['samlSessionIndex'] = auth.get_session_index()
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        if 'RelayState' in request.form and self_url != request.form['RelayState']:
            # To avoid 'Open Redirect' attacks, before execute the redirection confirm
            # the value of the request.form['RelayState'] is a trusted URL.
            return redirect(request.form['RelayState'])
        
    elif auth.get_settings().is_debug_active():
        print(auth.get_last_error_reason())
        raise(400)

@app.post('/saml/slo')
def post_saml_slo():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    name_id = session['samlNameId']
    name_id_format = session['samlNameIdFormat']
    name_id_nq = session['samlNameIdNameQualifier']
    name_id_spnq = session['samlNameIdSPNameQualifier']
    session_index = session['samlSessionIndex']
    session['method'] = None
    session['username'] = None
    session['duo_session'] = None
    session['samlUserdata'] = None
    session['samlNameId'] = None
    session['samlNameIdFormat'] = None
    session['samlNameIdNameQualifier'] = None
    session['samlNameIdSPNameQualifier'] = None
    session['samlSessionIndex'] = None
    return redirect(auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq))

##########################################
############## Duo OIDC SSO ##############
##########################################

from oidc.duo_oidc import OIDC_Client

oidc_client = OIDC_Client()

@app.post('/oidc/sso')
def post_oidc_sso():
    app_url = request.url
    if app_url.startswith('http://'):
        app_url = app_url.replace('http://', 'https://')
    authorize_url = oidc_client.get_authorize_url(app_url)
    return redirect(authorize_url)

@app.get('/oidc/authorize_result')
def get_oidc_authorize_result():
    code = request.args.get('code')
    state = request.args.get('state')
    app_url = request.base_url
    if app_url.startswith('http://'):
        app_url = app_url.replace('http://', 'https://')
    userinfo = oidc_client.get_userinfo(app_url, code, state)
    session['method'] = "Duo SSO with OIDC"
    session['username'] = userinfo['email']
    session['duo_session'] = userinfo['sub']
    return redirect('/home')

@app.post('/oidc/logout')
def post_oidc_logout():
    session['method'] = None
    session['username'] = None
    session['duo_session'] = None
    oidc_client.logout()
    return redirect('/login')

##########################################
################# Common #################
##########################################

@app.get('/')
def get_index():
    return redirect('/login')

@app.get('/login')
def get_login():
    return render_template('login.html')

@app.get('/home')
def get_home():
    if session.get('method'):
        return render_template(
            'home.html',
            method=session.get('method'),
            duo_session=session.get('duo_session'),
            username=session.get('username')
        )
    else:
        return redirect('/login')

if __name__ == '__main__':
    app.run(host="localhost", port=8000)
