import json, requests, os, random, string, base64

class OIDC_Client:

    def _generate_state(self):
        generator = random.SystemRandom()
        characters = string.ascii_letters + string.digits
        return ''.join(generator.choice(characters) for i in range(36))

    def __init__(self, custom_settings_path=None):
        # set settings.json path; default path: oidc/settings.json
        self._settings_path = "oidc/settings.json"
        if custom_settings_path:
            self._settings_path = custom_settings_path
        # read settings from json file
        settings_file = open(self._settings_path, "r")
        settings = json.loads(settings_file.read())
        settings_file.close()
        # query configuration information about Duo OIDC SSO via discovery URL
        self._discovery_url = settings['discovery_url']
        discovery = json.loads(requests.get(self._discovery_url).text)
        # initialize OIDC endpoints and parameters
        self._client_id = settings['client_id']
        self._client_secret = settings['client_secret']
        self._issuer = discovery['issuer']
        self._authorization_url = discovery['authorization_endpoint']
        self._token_url = discovery['token_endpoint']
        self._jwks_url = discovery['jwks_uri']
        self._userinfo_url = discovery['userinfo_endpoint']
        self._token_introspection_url = discovery['introspection_endpoint']
        self._scope = "openid"
        self._alg = "RS256"
        # query signing key(s) this relying party uses to validate signatures from Duo
        self._jwks = json.loads(requests.get(self._jwks_url).text)
        
    def get_authorize_url(self, app_url, nonce=None, code_challenge=None, code_challenge_method=None, login_hint=None, prompt=None, response_mode=None):
        self.authorize_state = self._generate_state()
        parameters = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": app_url.replace("sso", "authorize_result"),
            "scope": "openid profile email",
            "nonce": None,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "login_hint": login_hint,
            "prompt": prompt,
            "response_mode": response_mode,
            "state": self.authorize_state
        }
        uri_parameters = '&'.join(f"{k}={v}" for (k, v) in parameters.items() if v is not None)
        authorize_url = f"{self._authorization_url}?{uri_parameters}"
        return authorize_url

    def get_userinfo(self, app_url, code, state, code_verifier=None):
        if state != self.authorize_state:
            abort(400)
        # retrieve access token and id token
        headers = {
            "Content-type": "application/x-www-form-urlencoded"
        }
        payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": app_url
        }
        token = json.loads(requests.post(self._token_url, headers=headers, data=payload).text)
        print(token)
        access_token = token['access_token']
        id_token = token['id_token']
        expires_in = token['expires_in']

        # introspection of a retrieved token
        authz_bytes = f"{self._client_id}:{self._client_secret}".encode("ascii")
        authz_base64 = base64.b64encode(authz_bytes).decode("ascii")
        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {authz_base64}"
        }
        payload = {
            "token": access_token
        }
        token_introspection = json.loads(requests.post(self._token_introspection_url, headers=headers, data=payload).text)
        if token_introspection['active'] != True:
            abort(400)

        # user info of a retrieved token
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        userinfo = json.loads(requests.get(self._userinfo_url, headers=headers).text)
        return userinfo

    def logout(self):
        # to be implemented when Duo OIDC RP supports logout mechanism
        return
