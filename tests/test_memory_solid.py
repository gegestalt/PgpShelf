import pytest
from werkzeug.datastructures import FileStorage
from io import BytesIO
from app import app, db
from models import User, EncryptedFile
from sqlalchemy import inspect

@pytest.fixture
def client():
    """Set up the test client and mock database session."""
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

def get_auth_token(client, user_id="testuser", password="testpassword", email="test@example.com"):
    """Helper function to register a user and get auth token."""
    # Register user
    client.post('/auth/register', json={
        'user_id': user_id,
        'email': email,
        'password': password
    })
    
    # Login to get token
    response = client.post('/auth/login', json={
        'user_id': user_id,
        'password': password
    })
    return response.json['access_token']

def test_schema_initialized(client):
    """Ensure the in-memory database schema is initialized properly."""
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Include all expected tables
        expected_tables = {"user", "encrypted_file", "alembic_version"}
        
        assert set(tables) == expected_tables, f"Tables not initialized correctly, found: {tables}"

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
    assert "content" in response.json

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
