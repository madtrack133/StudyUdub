import sys
import os
import pytest

#make sure the root directory is in the path so we can import app.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  #disable CSRF for testing
    with app.test_client() as client:
        with app.app_context():
            db.create_all()  #create fresh tables
        yield client
        with app.app_context():
            db.drop_all()  # Clean up after test

def test_home_redirects(client):
    response = client.get('/')
    # Expect redirect to dashboard
    assert response.status_code == 302
    assert '/dashboard' in response.headers['Location']

def test_login_page_loads(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Log In' in response.data  #check if the login form is shown

def test_signup_page_loads(client):
    response = client.get('/signup')
    assert response.status_code == 200
    assert b'Sign Up' in response.data