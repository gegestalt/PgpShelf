from werkzeug.datastructures import FileStorage
from io import BytesIO
import pytest
from app import app, db
from models import User, EncryptedFile
from datetime import datetime

@pytest.fixture
def client():
    """Set up the test client and ensure a clean database state for testing."""
    app.testing = True
    client = app.test_client()

    # Reset the database
    with app.app_context():
        db.drop_all()
        db.create_all()

    yield client

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

def test_generate_keys(client):
    """Test key pair generation for a user."""
    token = get_auth_token(client)
    
    response = client.post('/file/generate_keys',
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200

def test_upload_file(client):
    """Test file upload for a user."""
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
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'multipart/form-data'
        })
    assert response.status_code == 200

def test_list_user_files(client):
    """Test listing files for a specific user."""
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
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'multipart/form-data'
        })
    assert upload_response.status_code == 200

    # List files
    response = client.get('/file/files',
        headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    files = response.json['files']
    assert len(files) > 0

def test_decrypt_file(client):
    """Test decrypting an uploaded file."""
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
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'multipart/form-data'
        })
    file_id = upload_response.json["file_id"]

    # Decrypt file
    response = client.post(f'/file/decrypt/download/{file_id}',
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.data == file_data

def test_list_all_files(client):
    """Test listing all files in the system."""
    token = get_auth_token(client)
    
    response = client.get('/file/files',
        headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
