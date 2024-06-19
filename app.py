import os
from flask import Flask, redirect, url_for, session, request, render_template, make_response
import msal
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Replace these values with your application's details
CLIENT_ID = 'c468c3dc-0559-41d5-a0c5-9c9e5a7d1a35'
CLIENT_SECRET = '8v78Q~b2jp0-tmDdE2REGC46hYs4N4f~n-gekauS'
TENANT_ID = '65b908be-db42-4118-8a9e-dfaa849664c9'
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = 'http://localhost:5015/getAToken'

SCOPE = ["User.Read"]  # Scope for Microsoft Graph API

# Initialize MSAL confidential client
msal_client = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET
)

@app.route('/')
def index():
    if not session.get('user'):
        return redirect(url_for('login'))
    user = session['user']
    email = user.get('mail', user.get('userPrincipalName', 'No email found'))
    return render_template('profile.html', user=user, email=email)

@app.route('/login')
def login():
    auth_url = msal_client.get_authorization_request_url(SCOPE, redirect_uri=REDIRECT_URI)
    return render_template('login.html', auth_url=auth_url)

@app.route('/getAToken')
def get_a_token():
    if 'code' in request.args:
        code = request.args['code']
        result = msal_client.acquire_token_by_authorization_code(
            code,
            scopes=SCOPE,
            redirect_uri=REDIRECT_URI
        )

        if 'access_token' in result:
            session['access_token'] = result['access_token']
            # Retrieve user information
            user_info = get_user_info(result['access_token'])
            session['user'] = user_info

            # Make additional request to set cookies
            payload = {
                "usr": "Administrator",
                "pwd": "2wsx1qaz"
            }
            make_cookie = requests.post("http://10.1.111.141:30419/login", json=payload)
            resp_cookie = make_cookie.json()

            # Redirect to external URL and set cookies
            response = make_response(redirect("http://localhost:5012/"))
            response.set_cookie('CSRF Token', resp_cookie.get('CSRF Token', ''))
            response.set_cookie('sid', resp_cookie.get('sid', ''))
            response.set_cookie('system_user', resp_cookie.get('system_user', ''))
            response.set_cookie('user_id', resp_cookie.get('user_id', ''))
            response.set_cookie('user_image', resp_cookie.get('user_image', ''))
            return response
        else:
            return "Authentication failed. Please try again."

    return "No code provided. Login failed."

def get_user_info(access_token):
    headers = {'Authorization': 'Bearer ' + access_token}
    user_info_response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
    return user_info_response.json()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, port=5015)
