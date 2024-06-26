import os
import json
import pytest
from main import APP

SECRET = 'TestSecret'
EMAIL = 'wolf@thedoor.com'
PASSWORD = 'huff-puff'

@pytest.fixture
def client():
    os.environ['JWT_SECRET'] = SECRET
    APP.config['TESTING'] = True
    client = APP.test_client()

    yield client

def test_health(client):
    response = client.get('/')
    assert response.status_code == 200
    assert response.json == "Healthy"


def test_auth(client):
    body = {'email': EMAIL, 'password': PASSWORD}
    response = client.post('/auth', data=json.dumps(body), content_type='application/json')

    assert response.status_code == 200
    assert 'token' in response.json

def test_auth_missing_credentials(client):
    body = {'email': EMAIL}
    response = client.post('/auth', data=json.dumps(body), content_type='application/json')

    assert response.status_code == 400
    assert 'message' in response.json

def test_decode_jwt(client):
    token = _get_token(client)
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/contents', headers=headers)

    assert response.status_code == 200
    assert 'email' in response.json
    assert 'exp' in response.json
    assert 'nbf' in response.json

def _get_token(client):
    body = {'email': EMAIL, 'password': PASSWORD}
    response = client.post('/auth', data=json.dumps(body), content_type='application/json')
    return response.json['token']
