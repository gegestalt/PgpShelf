import pytest
from app import app, db, User, EncryptedFile

@pytest.fixture
def client():
    """Set up the test client and ensure a clean state for testing."""
    app.testing = True
    client = app.test_client()

    # Reset database
    with app.app_context():
        db.drop_all()
        db.create_all()

    yield client


def test_generate_keys_and_save_to_db(client):
    """Test if key generation saves public/private keys to the database."""
    response = client.post('/generate_keys', data={"user_id": "user1"})
    assert response.status_code == 200
    assert "Keys generated and saved successfully." in response.get_json()["message"]

    # Verify the keys are saved in the database
    with app.app_context():
        user = User.query.filter_by(user_id="user1").first()
        assert user is not None, "User not found in database."
        assert user.public_key is not None, "Public key not saved."
        assert user.private_key is not None, "Private key not saved."


def test_upload_and_list_files(client):
    """Test the entire flow: generate keys, upload a file, and list files."""
    response = client.post('/generate_keys', data={"user_id": "user1"})
    assert response.status_code == 200

    file_data = b"This is a test dummy file."
    response = client.post('/upload', data={
        "user_id": "user1",
        "file": (file_data, "dummy.txt")
    })
    assert response.status_code == 200
    assert "File uploaded and encrypted successfully." in response.get_json()["message"]

    with app.app_context():
        files = EncryptedFile.query.filter_by(user_id="user1").all()
        assert len(files) == 1
        assert files[0].file_name == "dummy.txt"

    # List files for the user
    response = client.get('/files?user_id=user1')
    assert response.status_code == 200
    file_list = response.get_json()["files"]
    assert len(file_list) == 1
    assert file_list[0]["file_name"] == "dummy.txt"

def test_list_all_files(client):
    """Test listing all files uploaded to the server."""
    response = client.get('/list')
    assert response.status_code == 200
    assert "files" in response.get_json()
    assert len(response.get_json()["files"]) == 0

    client.post('/generate_keys', data={"user_id": "user1"})
    client.post('/generate_keys', data={"user_id": "user2"})

    client.post('/upload', data={
        "user_id": "user1",
        "file": (b"User1's file data", "user1_file.txt")
    })
    client.post('/upload', data={
        "user_id": "user2",
        "file": (b"User2's file data", "user2_file.txt")
    })

    # Step 2: List all files after upload
    response = client.get('/list')
    assert response.status_code == 200

    file_list = response.get_json()["files"]
    assert len(file_list) == 2
    assert file_list[0]["file_name"] == "user1_file.txt"
    assert file_list[0]["user_id"] == "user1"
    assert file_list[1]["file_name"] == "user2_file.txt"
    assert file_list[1]["user_id"] == "user2"

    for file in file_list:
        assert "encrypted_content" in file
        assert isinstance(file["encrypted_content"], str)


def test_list_files_no_files(client):
    """Test listing files for a user with no uploads."""
    response = client.get('/files?user_id=user1')
    assert response.status_code == 200
    assert response.get_json()["message"] == "No files found for this user."


def test_upload_with_no_keys(client):
    """Test uploading a file without generating keys for the user."""
    file_data = b"This is a test dummy file."
    response = client.post('/upload', data={
        "user_id": "user1",
        "file": (file_data, "dummy.txt")
    })
    assert response.status_code == 404
    assert "User not found." in response.get_json()["error"]
