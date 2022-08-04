import requests
import urllib.parse as urlparse

RVT = '__RequestVerificationToken'

URL_BASE = 'https://example.com/'
USERNAME = 'username'
PASSWORD = 'password'

def _find_value(body: str, name: str) -> str:
    idx = body.find(f'name="{name}"')
    if idx == -1:
        idx = body.find(f'name=\'{name}\'')
    if idx == -1:
        raise Exception('failed to find value for given name')
    idx = body.find('value=', idx) + 7
    end_char = body[idx-1]
    return body[idx:body.find(end_char, idx)]

# a function that attempts login into the application, returning the whole blazor_descriptor for websocket initialisation
def login(sess: requests.Session):
    resp = sess.get(URL_BASE)
    auth_target = resp.url
    rvt = _find_value(resp.text, RVT)

    resp = sess.post(auth_target, data={
        'username': USERNAME,
        'password': PASSWORD,
        'button': 'login',
        RVT: rvt,
    })

    body = resp.text
    code = _find_value(body, 'code')
    scope = _find_value(body, 'scope')
    state = _find_value(body, 'state')
    session_state = _find_value(body, 'session_state')

    resp = sess.post(urlparse.urljoin(URL_BASE, 'signin-oidc'), data={
        'code': code,
        'scope': scope,
        'state': state,
        'session_state': session_state,
    })

    body = resp.text
    idx = body.find('<!--Blazor:') + 11
    blazor_descriptor = body[idx:body.find('-->', idx)]

    return blazor_descriptor