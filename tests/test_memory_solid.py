import pytest
from unittest.mock import patch, MagicMock
from werkzeug.datastructures import FileStorage
from io import BytesIO
from app import app, db
from models import User, EncryptedFile


@pytest.fixture
def client():
    """Set up the test client and mock database session."""
    app.testing = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory DB for tests

    # Initialize the test client
    client = app.test_client()

    # Override the db session and ensure no real database interaction
    with patch('app.db.session') as mock_db_session:
        yield client

    # Cleanup after tests
    with patch('app.db.session.remove') as mock_remove:
        mock_remove()


def test_generate_keys(client):
    """Test key pair generation for a user."""
    user_id = "test_user"
    passphrase = "test_passphrase"

    with patch('models.User.query.filter_by') as mock_query:
        mock_user = MagicMock()
        mock_user.public_key = 'mock_public_key'
        mock_user.private_key = 'mock_private_key'
        mock_query.return_value.first.return_value = mock_user

        with app.app_context():
            response = client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})

    assert response.status_code == 200
    assert "PGP keys generated and saved successfully." in response.json["message"]
    print(f"Debug: Key pair generated for user: {user_id}")
        
    # Check that the mocked user has the expected attributes
    assert mock_user.public_key is not None, "Public key not mocked correctly."
    assert mock_user.private_key is not None, "Private key not mocked correctly."


def test_upload_file(client):
    """Test file upload for a user."""
    user_id = "test_user"
    passphrase = "test_passphrase"

    with patch('models.EncryptedFile.save') as mock_save:
        mock_save.return_value = None  # Mock the save method to prevent actual DB interaction

        file_data = b"This is a test file for encryption and decryption."
        file_storage = FileStorage(
            stream=BytesIO(file_data),
            filename="test_file.txt",
            content_type="text/plain"
        )

        with app.app_context():
            response = client.post('/upload', data={
                "user_id": user_id,
                "file": file_storage
            }, content_type='multipart/form-data')

    assert response.status_code == 200
    assert "File uploaded and encrypted successfully." in response.json["message"]
    print("Debug: File uploaded and encrypted.")


def test_list_user_files(client):
    """Test listing files for a specific user."""
    user_id = "test_user"
    passphrase = "test_passphrase"

    with patch('models.EncryptedFile.query.filter_by') as mock_query:
        mock_file = MagicMock()
        mock_file.uploaded_by = user_id
        mock_file.upload_date = '2025-01-12'
        mock_query.return_value.all.return_value = [mock_file]

        # Upload file (simulating key generation and file upload)
        file_data = b"This is a test file for encryption and decryption."
        file_storage = FileStorage(
            stream=BytesIO(file_data),
            filename="test_file.txt",
            content_type="text/plain"
        )
        upload_response = client.post('/upload', data={
            "user_id": user_id,
            "file": file_storage
        }, content_type='multipart/form-data')
        assert upload_response.status_code == 200

        # Now, list the files
        with app.app_context():
            response = client.get(f'/files?user_id={user_id}')
        
    assert response.status_code == 200
    file_list = response.json["files"]
    print(f"Debug: File list response={file_list}")
    assert len(file_list) == 1, "File list does not contain the uploaded file."
    assert file_list[0]["uploaded_by"] == user_id, "Uploaded by user ID mismatch."
    assert "upload_date" in file_list[0], "Upload date not found in response."


def test_decrypt_file(client):
    """Test decrypting an uploaded file."""
    user_id = "test_user"
    passphrase = "test_passphrase"
    
    with patch('models.EncryptedFile.query.filter_by') as mock_query:
        mock_file = MagicMock()
        mock_file.content = b"This is a test file for encryption and decryption."
        mock_query.return_value.first.return_value = mock_file

        # Upload file (simulating key generation and file upload)
        file_data = b"This is a test file for encryption and decryption."
        file_storage = FileStorage(
            stream=BytesIO(file_data),
            filename="test_file.txt",
            content_type="text/plain"
        )
        upload_response = client.post('/upload', data={
            "user_id": user_id,
            "file": file_storage
        }, content_type='multipart/form-data')
        file_id = upload_response.json.get("file_id")

        # Now, simulate file decryption
        with app.app_context():
            response = client.post('/decrypt', data={
                "user_id": user_id,
                "file_id": file_id,
                "passphrase": passphrase
            })
    
    assert response.status_code == 200
    decrypted_content = response.json["content"]
    print(f"Debug: Decrypted content={decrypted_content}")
    assert decrypted_content == file_data.decode("utf-8"), "Decrypted content mismatch."


def test_list_all_files(client):
    """Test listing all files in the system."""
    user_id = "test_user"
    passphrase = "test_passphrase"
    
    with patch('models.EncryptedFile.query.all') as mock_query:
        mock_file = MagicMock()
        mock_file.file_name = "test_file.txt"
        mock_file.user_id = user_id
        mock_file.upload_date = '2025-01-12'
        mock_query.return_value = [mock_file]

        # Upload file (simulating key generation and file upload)
        file_data = b"This is a test file for encryption and decryption."
        file_storage = FileStorage(
            stream=BytesIO(file_data),
            filename="test_file.txt",
            content_type="text/plain"
        )
        client.post('/upload', data={
            "user_id": user_id,
            "file": file_storage
        }, content_type='multipart/form-data')

        # Now, list all files
        with app.app_context():
            response = client.get('/list_all')
        
    assert response.status_code == 200
    all_files = response.json["files"]
    print(f"Debug: All files response={all_files}")
    assert len(all_files) == 1, "Unexpected number of files in the system."
    assert all_files[0]["file_name"] == "test_file.txt", "Listed file name mismatch."
    assert all_files[0]["user_id"] == user_id, "Listed file user_id mismatch."
    assert "upload_date" in all_files[0], "Upload date not found in response."
