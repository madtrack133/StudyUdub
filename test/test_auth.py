import pytest
from models import Student

def signup(client, email="test@uni.edu", password="Aa1!aaaa", uni="U1001"):
    return client.post("/signup", data={
        "email": email,
        "password": password,
        "confirm_password": password,
        "first_name": "Test",
        "last_name": "User",
        "uniStudentID": uni
    }, follow_redirects=True)

def login(client, email, password):
    return client.post("/login", data={
        "email": email,
        "password": password
    }, follow_redirects=True)


def test_protected_route_requires_login(client):
    # dashboard is protected
    rv = client.get("/dashboard")
    # you'll be redirected to /login?next=/dashboard
    assert rv.status_code == 302
    assert "/login" in rv.headers["Location"]

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

def test_forgot_password_page_loads(client):
    response = client.get('/forgot')
    assert response.status_code == 200
    assert b'name="email"' in response.data

def test_upload_requires_login(client):
    response = client.get('/upload')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']