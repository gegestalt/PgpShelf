import pytest
from flask import Flask
from models import db, User, EncryptedFile
from werkzeug.datastructures import FileStorage
import os
from routes.auth import auth_bp
from routes.file_routes import file_bp
from flask_jwt_extended import JWTManager

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
    
    db.init_app(app)
    JWTManager(app)
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(file_bp, url_prefix='/file')
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_direct_file_share(client, app):
    """Test sharing a file directly with a recipient using their public key."""
    # Setup users
    bob_token = get_auth_token(client, "bob", "bobpass", "bob@example.com")
    alice_token = get_auth_token(client, "alice", "alicepass", "alice@example.com")
    
    # Generate keys for both users
    client.post('/file/generate_keys',
        data={"passphrase": "bob_secret"},
        headers={'Authorization': f'Bearer {bob_token}'})
    
    client.post('/file/generate_keys',
        data={"passphrase": "alice_secret"},
        headers={'Authorization': f'Bearer {alice_token}'})

    # Get a test file from upload directory
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'upload')
    test_file = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))][0]
    file_path = os.path.join(upload_dir, test_file)
    
    # Read original file content for later comparison
    with open(file_path, 'rb') as f:
        original_content = f.read()
        
    # Bob shares file directly with Alice
    with open(file_path, 'rb') as f:
        file_storage = FileStorage(
            stream=open(file_path, 'rb'),
            filename=test_file,
            content_type='application/octet-stream'
        )
        
        # Share file directly with Alice using her public key
        share_response = client.post('/file/share_with',
            data={
                "file": file_storage,
                "recipient_id": "alice"
            },
            headers={'Authorization': f'Bearer {bob_token}'},
            content_type='multipart/form-data')
        
        file_storage.stream.close()
    
    assert share_response.status_code == 200
    shared_file_id = share_response.json['file_id']
    
    # Verify Alice can decrypt and download the file
    decrypt_response = client.post(
        f'/file/decrypt/download/{shared_file_id}',
        data={"passphrase": "alice_secret"},
        headers={'Authorization': f'Bearer {alice_token}'})
    
    assert decrypt_response.status_code == 200
    assert decrypt_response.data == original_content

def get_auth_token(client, user_id, password, email):
    """Helper function to register a user and get auth token."""
    client.post('/auth/register', json={
        'user_id': user_id,
        'email': email,
        'password': password
    })
    
    response = client.post('/auth/login', json={
        'user_id': user_id,
        'password': password
    })
    return response.json['access_token'] 

def test_unauthorized_file_share_access(client, app):
    """Test that only the intended recipient can decrypt the shared file."""
    # Setup users: Bob (sender), Alice (intended recipient), Eve (unauthorized user)
    bob_token = get_auth_token(client, "bob", "bobpass", "bob@example.com")
    alice_token = get_auth_token(client, "alice", "alicepass", "alice@example.com")
    eve_token = get_auth_token(client, "eve", "evepass", "eve@example.com")
    
    # Generate keys for all users
    for user, token, passphrase in [
        ("bob", bob_token, "bob_secret"),
        ("alice", alice_token, "alice_secret"),
        ("eve", eve_token, "eve_secret")
    ]:
        client.post('/file/generate_keys',
            data={"passphrase": passphrase},
            headers={'Authorization': f'Bearer {token}'})

    # Get a test file from upload directory
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'upload')
    test_file = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))][0]
    file_path = os.path.join(upload_dir, test_file)
    
    # Bob shares file with Alice
    with open(file_path, 'rb') as f:
        file_storage = FileStorage(
            stream=open(file_path, 'rb'),
            filename=test_file,
            content_type='application/octet-stream'
        )
        
        share_response = client.post('/file/share_with',
            data={
                "file": file_storage,
                "recipient_id": "alice"
            },
            headers={'Authorization': f'Bearer {bob_token}'},
            content_type='multipart/form-data')
        
        file_storage.stream.close()
    
    assert share_response.status_code == 200
    shared_file_id = share_response.json['file_id']
    
    # Eve attempts to decrypt Alice's file
    eve_decrypt_response = client.post(
        f'/file/decrypt/download/{shared_file_id}',
        data={"passphrase": "eve_secret"},
        headers={'Authorization': f'Bearer {eve_token}'})
    
    # Verify Eve's attempt is denied
    assert eve_decrypt_response.status_code == 403
    assert "not authorized" in eve_decrypt_response.json["error"].lower()
    
    # Verify Bob (sender) cannot decrypt the file either
    bob_decrypt_response = client.post(
        f'/file/decrypt/download/{shared_file_id}',
        data={"passphrase": "bob_secret"},
        headers={'Authorization': f'Bearer {bob_token}'})
    
    assert bob_decrypt_response.status_code == 403
    assert "not authorized" in bob_decrypt_response.json["error"].lower()
    
    # Verify Alice (intended recipient) can decrypt the file
    alice_decrypt_response = client.post(
        f'/file/decrypt/download/{shared_file_id}',
        data={"passphrase": "alice_secret"},
        headers={'Authorization': f'Bearer {alice_token}'})
    
    assert alice_decrypt_response.status_code == 200 