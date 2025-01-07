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

def test_generate_keys(client):
    """Test key pair generation for a user."""
    user_id = "test_user"
    passphrase = "test_passphrase"
    response = client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})
    assert response.status_code == 200
    assert "PGP keys generated and saved successfully." in response.json["message"]
    print("Debug: Key pair generated successfully.")

    with app.app_context():
        user = User.query.filter_by(user_id=user_id).first()
        print(f"Debug: User in database={user is not None}")
        assert user is not None, "User not found in database."
        assert user.public_key is not None, "Public key not saved."
        assert user.private_key is not None, "Private key not saved."

def test_upload_file(client):
    """Test file upload for a user."""
    user_id = "test_user"
    passphrase = "test_passphrase"
    client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})

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
    passphrase = "test_passphrase"

    client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})

    # Step 2: Upload the file
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
    assert upload_response.status_code == 200, f"File upload failed: {upload_response.json}"

    # Debug: Check the database state
    with app.app_context():
        files_in_db = EncryptedFile.query.filter_by(user_id=user_id).all()
        print(f"Debug: Files in database={files_in_db}")
        assert len(files_in_db) > 0, "No files found in the database after upload."

    # Step 3: List files
    response = client.get(f'/files?user_id={user_id}')
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    file_list = response.json["files"]
    print(f"Debug: File list response={file_list}")
    assert len(file_list) == 1, "File list does not contain the uploaded file."
    assert file_list[0]["uploaded_by"] == user_id, "Uploaded by user ID mismatch."
    assert "upload_date" in file_list[0], "Upload date not found in response."

def test_decrypt_file(client):
    """Test decrypting an uploaded file."""
    user_id = "test_user"
    passphrase = "test_passphrase"
    # Ensure the user exists and a file is uploaded
    client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})
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
        "file_id": file_id,
        "passphrase": passphrase
    })
    print(f"Debug: Decrypt response={response.json}")
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    decrypted_content = response.json["content"]
    assert decrypted_content == file_data.decode("utf-8"), "Decrypted content mismatch."

def test_list_all_files(client):
    """Test listing all files in the system."""
    user_id = "test_user"
    passphrase = "test_passphrase"
    # Ensure the user exists and a file is uploaded
    client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})
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

    response = client.get('/list_all')
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    all_files = response.json["files"]
    print(f"Debug: All files response={all_files}")
    assert len(all_files) == 1, "Unexpected number of files in the system."
    assert all_files[0]["file_name"] == "test_file.txt", "Listed file name mismatch."
    assert all_files[0]["user_id"] == user_id, "Listed file user_id mismatch."
    assert "upload_date" in all_files[0], "Upload date not found in response."

def test_generate_new_key_pair_for_existing_user(client):
    """Test generating a new key pair for a user who has been registered before."""
    user_id = "existing_user"
    passphrase = "initial_passphrase"

    # Step 1: Register the user and generate the initial key pair
    response = client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})
    assert response.status_code == 200
    assert "PGP keys generated and saved successfully." in response.json["message"]

    response = client.post('/generate_keys', data={"user_id": user_id, "passphrase": "new_passphrase"})
    assert response.status_code == 400
    assert "User already exists with generated keys." in response.json["error"]

def test_generate_new_key_pair_after_deletion(client):
    """Test generating a new key pair for a user after deleting the old key pair."""
    user_id = "existing_user"
    passphrase = "initial_passphrase"

    # Step 1: Register the user and generate the initial key pair
    response = client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})
    assert response.status_code == 200
    assert "PGP keys generated and saved successfully." in response.json["message"]

    # Step 2: Delete the user's key pair from the database
    with app.app_context():
        user = User.query.filter_by(user_id=user_id).first()
        assert user is not None, "User not found in database."
        db.session.delete(user)
        db.session.commit()

    # Step 3: Attempt to generate a new key pair for the same user
    response = client.post('/generate_keys', data={"user_id": user_id, "passphrase": "new_passphrase"})
    assert response.status_code == 200
    assert "PGP keys generated and saved successfully." in response.json["message"]

    # Verify the new key pair is saved in the database
    with app.app_context():
        user = User.query.filter_by(user_id=user_id).first()
        assert user is not None, "User not found in database after generating new key pair."
        assert user.public_key is not None, "Public key not saved for new key pair."
        assert user.private_key is not None, "Private key not saved for new key pair."