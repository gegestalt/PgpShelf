import pytest
from werkzeug.security import generate_password_hash
from flask import Flask
from flask_jwt_extended import JWTManager
from models import db, User
import json

# Import your routes
from routes.auth import auth_bp
from routes.file_routes import file_bp

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    app = Flask(__name__)
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'TESTING': True,
        'JWT_SECRET_KEY': 'test-secret-key'
    })
    
    # Initialize extensions
    db.init_app(app)
    JWTManager(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(file_bp, url_prefix='/file')
    
    # Create tables and context
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def app_context(app):
    with app.app_context():
        yield

def test_user_registration(client, app_context):
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
    
    user = User.query.filter_by(user_id='testuser').first()
    assert user is not None
    assert user.email == 'test@example.com'

def test_user_login(client, app_context):
    """Test user login endpoint."""
    # Create a test user first
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

def test_protected_route(client, app_context):
    """Test protected route access with JWT token."""
    # Create and login user first
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
    response = client.get('/file/files',  # Changed from /protected to /file/files
                         headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200

def test_duplicate_registration(client, app_context):
    """Test registration with duplicate user_id."""
    # Register first user
    client.post('/auth/register', json={
        'user_id': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword'
    })
    
    # Try to register duplicate user
    response = client.post('/auth/register', json={
        'user_id': 'testuser',
        'email': 'another@example.com',
        'password': 'anotherpassword'
    })
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'already exists' in data['error'].lower()

def test_invalid_login(client, app_context):
    """Test login with invalid credentials."""
    # Create a test user
    user = User(
        user_id='testuser',
        email='test@example.com'
    )
    user.set_password('testpassword')
    db.session.add(user)
    db.session.commit()
    
    # Test wrong password
    response = client.post('/auth/login', json={
        'user_id': 'testuser',
        'password': 'wrongpassword'
    })
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'invalid credentials' in data['error'].lower()

def test_protected_route_without_token(client, app_context):
    """Test accessing protected route without token."""
    response = client.get('/file/files')  # Changed from /protected to /file/files
    assert response.status_code == 401 