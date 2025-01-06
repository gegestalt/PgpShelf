from werkzeug.datastructures import FileStorage
from io import BytesIO
import pytest
from app import app, db, User, EncryptedFile
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

def test_generate_keys(client):
    """Test key pair generation for a user."""
    user_id = "test_user"
    response = client.post('/generate_keys', data={"user_id": user_id})
    assert response.status_code == 200
    assert "Keys generated and saved successfully." in response.json["message"]
    print("Debug: Key pair generated successfully.")

    # Verify user is saved in the database
    with app.app_context():
        user = User.query.filter_by(user_id=user_id).first()
        print(f"Debug: User in database={user is not None}")
        assert user is not None, "User not found in database."
        assert user.public_key is not None, "Public key not saved."
        assert user.private_key is not None, "Private key not saved."

def test_upload_file(client):
    """Test file upload for a user."""
    user_id = "test_user"
    # Ensure the user exists by generating keys
    client.post('/generate_keys', data={"user_id": user_id})

    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )

    response = client.post('/upload', data={
        "user_id": user_id,
        "file": file_storage
    }, content_type='multipart/form-data')
    print(f"Debug: Upload response={response.json}")
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    assert "File uploaded and encrypted successfully." in response.json["message"]

def test_list_user_files(client):
    """Test listing files for a specific user."""
    user_id = "test_user"
    # Ensure the user exists and a file is uploaded
    client.post('/generate_keys', data={"user_id": user_id})
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

    response = client.get(f'/files?user_id={user_id}')
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    file_list = response.json["files"]
    print(f"Debug: File list response={file_list}")
    assert len(file_list) == 1, "File list does not contain the uploaded file."
    assert file_list[0]["file_name"] == "test_file.txt", "Uploaded file name mismatch."

def test_decrypt_file(client):
    """Test decrypting an uploaded file."""
    user_id = "test_user"
    # Ensure the user exists and a file is uploaded
    client.post('/generate_keys', data={"user_id": user_id})
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

    response = client.post('/decrypt', data={
        "user_id": user_id,
        "file_id": file_id
    })
    print(f"Debug: Decrypt response={response.json}")
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    decrypted_content = response.json["content"]
    assert decrypted_content == file_data.decode("utf-8"), "Decrypted content mismatch."

def test_list_all_files(client):
    """Test listing all files in the system."""
    user_id = "test_user"
    # Ensure the user exists and a file is uploaded
    client.post('/generate_keys', data={"user_id": user_id})
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

    response = client.get('/list')
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    all_files = response.json["files"]
    print(f"Debug: All files response={all_files}")
    assert len(all_files) == 1, "Unexpected number of files in the system."
    assert all_files[0]["file_name"] == "test_file.txt", "Listed file name mismatch."
    assert all_files[0]["user_id"] == user_id, "Listed file user_id mismatch."
