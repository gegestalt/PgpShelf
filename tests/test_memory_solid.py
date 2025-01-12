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
