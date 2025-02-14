import pytest
from werkzeug.datastructures import FileStorage
from io import BytesIO
from flask import Flask
from flask_jwt_extended import JWTManager
from models import db, User, EncryptedFile
from sqlalchemy import inspect

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

def test_schema_initialized(app):
    """Ensure the in-memory database schema is initialized properly."""
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        expected_tables = {"user", "encrypted_file"}
        assert set(tables) == expected_tables, f"Tables not initialized correctly, found: {tables}"

def get_auth_token(client, user_id="testuser", password="testpassword", email="test@example.com"):
    """Helper function to register a user and get auth token."""
    # Register user
    register_response = client.post('/auth/register', json={
        'user_id': user_id,
        'email': email,
        'password': password
    })
    assert register_response.status_code == 201, f"Registration failed: {register_response.data}"
    
    # Login to get token
    login_response = client.post('/auth/login', json={
        'user_id': user_id,
        'password': password
    })
    assert login_response.status_code == 200, f"Login failed: {login_response.data}"
    
    return login_response.json['access_token']

def test_generate_keys(client):
    """Test key pair generation for a user."""
    # Get auth token first
    token = get_auth_token(client)
    
    response = client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 200
    assert "PGP keys generated and saved successfully." in response.json["message"]

def test_upload_file(client):
    """Test file upload for a user."""
    # Get auth token
    token = get_auth_token(client)
    
    # Generate keys first
    client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})

    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )

    response = client.post('/file/upload', 
        data={"file": file_storage},
        headers={'Authorization': f'Bearer {token}'},
        content_type='multipart/form-data')
        
    assert response.status_code == 200

def test_list_user_files(client):
    """Test listing files for a specific user."""
    # Get auth token
    token = get_auth_token(client)
    
    # Generate keys first
    client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})

    # Upload file
    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )
    
    client.post('/file/upload', 
        data={"file": file_storage},
        headers={'Authorization': f'Bearer {token}'},
        content_type='multipart/form-data')

    # List files
    response = client.get('/file/files',
        headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    file_list = response.json["files"]
    assert len(file_list) > 0, "No files found"

def test_decrypt_file(client):
    """Test decrypting an uploaded file."""
    # Get auth token
    token = get_auth_token(client)
    
    # Generate keys first
    client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})

    # Upload file
    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )
    
    upload_response = client.post('/file/upload', 
        data={"file": file_storage},
        headers={'Authorization': f'Bearer {token}'},
        content_type='multipart/form-data')
    assert upload_response.status_code == 200
    file_id = upload_response.json["file_id"]

    # Decrypt file
    response = client.post('/file/decrypt', 
        data={
            "file_id": file_id,
            "passphrase": "test_passphrase"
        },
        headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 200
    assert response.headers['Content-Type'] in ['text/plain', 'application/octet-stream']
    assert 'Content-Disposition' in response.headers
    assert 'test_file.txt' in response.headers['Content-Disposition']
    assert response.data == file_data

def test_unauthorized_file_decrypt(client):
    """Test that a user cannot decrypt another user's file."""
    # Create first user and upload a file
    token1 = get_auth_token(client, 
        user_id="user1", 
        password="password1", 
        email="user1@example.com")
    
    # Generate keys for first user
    client.post('/file/generate_keys', 
        data={"passphrase": "user1_passphrase"},
        headers={'Authorization': f'Bearer {token1}'})

    # Upload file as first user
    file_data = b"Secret data that user2 shouldn't see"
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="secret.txt",
        content_type="text/plain"
    )
    
    upload_response = client.post('/file/upload', 
        data={"file": file_storage},
        headers={'Authorization': f'Bearer {token1}'},
        content_type='multipart/form-data')
    assert upload_response.status_code == 200
    file_id = upload_response.json["file_id"]

    # Create second user and try to decrypt first user's file
    token2 = get_auth_token(client, 
        user_id="user2", 
        password="password2", 
        email="user2@example.com")
    
    # Generate keys for second user
    client.post('/file/generate_keys', 
        data={"passphrase": "user2_passphrase"},
        headers={'Authorization': f'Bearer {token2}'})

    # Attempt to decrypt file as second user
    response = client.post('/file/decrypt', 
        data={
            "file_id": file_id,
            "passphrase": "user2_passphrase"
        },
        headers={'Authorization': f'Bearer {token2}'})
    
    # Should get a 403 Forbidden response
    assert response.status_code == 403
    assert "error" in response.json
    assert "not authorized" in response.json["error"].lower()

def test_decrypt_file_info(client):
    """Test getting decrypt info for a file."""
    # Get auth token
    token = get_auth_token(client)
    
    # Generate keys first
    client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})

    # Upload file
    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )
    
    upload_response = client.post('/file/upload', 
        data={"file": file_storage},
        headers={'Authorization': f'Bearer {token}'},
        content_type='multipart/form-data')
    assert upload_response.status_code == 200
    file_id = upload_response.json["file_id"]

    # Get decrypt info
    response = client.post('/file/decrypt/info', 
        data={"file_id": file_id},
        headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 200
    assert "file_name" in response.json
    assert "file_id" in response.json
    assert "upload_date" in response.json
    assert "download_url" in response.json
    assert response.json["file_name"] == "test_file.txt"
    assert response.json["file_id"] == file_id

def test_decrypt_file_download(client):
    """Test downloading a decrypted file."""
    # Get auth token
    token = get_auth_token(client)
    
    # Generate keys first
    client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})

    # Upload file
    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )
    
    upload_response = client.post('/file/upload', 
        data={"file": file_storage},
        headers={'Authorization': f'Bearer {token}'},
        content_type='multipart/form-data')
    assert upload_response.status_code == 200
    file_id = upload_response.json["file_id"]

    # Download decrypted file
    response = client.post(f'/file/decrypt/download/{file_id}', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 200
    assert response.headers['Content-Type'] in ['text/plain', 'application/octet-stream']
    assert 'Content-Disposition' in response.headers
    assert 'test_file.txt' in response.headers['Content-Disposition']
    assert response.data == file_data

def test_unauthorized_file_decrypt_download(client):
    """Test that a user cannot download another user's decrypted file."""
    # Create first user and upload a file
    token1 = get_auth_token(client, 
        user_id="user1", 
        password="password1", 
        email="user1@example.com")
    
    # Generate keys for first user
    client.post('/file/generate_keys', 
        data={"passphrase": "user1_passphrase"},
        headers={'Authorization': f'Bearer {token1}'})

    # Upload file as first user
    file_data = b"Secret data that user2 shouldn't see"
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="secret.txt",
        content_type="text/plain"
    )
    
    upload_response = client.post('/file/upload', 
        data={"file": file_storage},
        headers={'Authorization': f'Bearer {token1}'},
        content_type='multipart/form-data')
    assert upload_response.status_code == 200
    file_id = upload_response.json["file_id"]

    # Create second user
    token2 = get_auth_token(client, 
        user_id="user2", 
        password="password2", 
        email="user2@example.com")

    # Try to get decrypt info as second user
    info_response = client.post('/file/decrypt/info', 
        data={"file_id": file_id},
        headers={'Authorization': f'Bearer {token2}'})
    assert info_response.status_code == 403
    assert "not authorized" in info_response.json["error"].lower()

    # Try to download file as second user
    download_response = client.post(f'/file/decrypt/download/{file_id}', 
        data={"passphrase": "user2_passphrase"},
        headers={'Authorization': f'Bearer {token2}'})
    assert download_response.status_code == 403
    assert "not authorized" in download_response.json["error"].lower()
