import pytest
from werkzeug.security import generate_password_hash
from app import app, db
from models import User
import json

@pytest.fixture
def client():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

def test_user_registration(client):
    """Test user registration endpoint."""
    response = client.post('/auth/register', json={
        'user_id': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword'
    })
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'message' in data
    assert 'User registered successfully' in data['message']
    
    with app.app_context():
        user = User.query.filter_by(user_id='testuser').first()
        assert user is not None
        assert user.email == 'test@example.com'

def test_user_login(client):
    """Test user login endpoint."""
    # Create a test user first
    with app.app_context():
        user = User(
            user_id='testuser',
            email='test@example.com'
        )
        user.set_password('testpassword')
        db.session.add(user)
        db.session.commit()
    
    # Test login
    response = client.post('/auth/login', json={
        'user_id': 'testuser',
        'password': 'testpassword'
    })
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data

def test_protected_route(client):
    """Test protected route access with JWT token."""
    # Create and login user first
    with app.app_context():
        user = User(
            user_id='testuser',
            email='test@example.com'
        )
        user.set_password('testpassword')
        db.session.add(user)
        db.session.commit()
    
    # Login to get token
    login_response = client.post('/auth/login', json={
        'user_id': 'testuser',
        'password': 'testpassword'
    })
    token = json.loads(login_response.data)['access_token']
    
    # Test protected route
    response = client.get('/protected', 
                         headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200 