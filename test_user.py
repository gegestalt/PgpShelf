import pytest
from app import app, db
from models import User, EncryptedFile
from datetime import datetime
from werkzeug.datastructures import FileStorage
from io import BytesIO

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

def test_user_registration_and_upload(client):
    """Test user registration, file upload, and listing."""
    # Step 1: Register User 1
    user1_id = "user1"
    user1_name = "Test User 1"
    response = client.post('/generate_keys', data={"user_id": user1_id})
    assert response.status_code == 200
    assert "Keys generated and saved successfully." in response.json["message"]
    
    # Verify User 1 in the database
    with app.app_context():
        user1 = User.query.filter_by(user_id=user1_id).first()
        assert user1 is not None, "User 1 not found in database."
        assert user1.public_key is not None, "Public key for User 1 not saved."
        assert user1.private_key is not None, "Private key for User 1 not saved."
        user1.key_generation_date = datetime.now()
        user1.user_name = user1_name
        db.session.commit()

    # Step 2: User 1 uploads a file
    file_data1 = b"This is User 1's test file."
    file_storage1 = FileStorage(
        stream=BytesIO(file_data1),
        filename="user1_file.txt",
        content_type="text/plain"
    )
    response = client.post('/upload', data={
        "user_id": user1_id,
        "file": file_storage1
    }, content_type='multipart/form-data')
    assert response.status_code == 200
    assert "File uploaded and encrypted successfully." in response.json["message"]

    # Step 3: Register User 2
    user2_id = "user2"
    user2_name = "Test User 2"
    response = client.post('/generate_keys', data={"user_id": user2_id})
    assert response.status_code == 200
    assert "Keys generated and saved successfully." in response.json["message"]

    with app.app_context():
        user2 = User.query.filter_by(user_id=user2_id).first()
        assert user2 is not None, "User 2 not found in database."
        assert user2.public_key is not None, "Public key for User 2 not saved."
        assert user2.private_key is not None, "Private key for User 2 not saved."
        user2.key_generation_date = datetime.now()
        user2.user_name = user2_name
        db.session.commit()

    # Step 4: User 2 lists all files
    response = client.get('/list_all')
    assert response.status_code == 200
    all_files = response.json["files"]
    assert len(all_files) == 1, "Expected 1 file in the system."
    assert all_files[0]["file_name"] == "user1_file.txt", "User 1's file not listed."

    # Step 5: User 2 uploads a file
    file_data2 = b"This is User 2's test file."
    file_storage2 = FileStorage(
        stream=BytesIO(file_data2),
        filename="user2_file.txt",
        content_type="text/plain"
    )
    response = client.post('/upload', data={
        "user_id": user2_id,
        "file": file_storage2
    }, content_type='multipart/form-data')
    assert response.status_code == 200
    assert "File uploaded and encrypted successfully." in response.json["message"]

    # Step 6: Verify all files in the system
    response = client.get('/list_all')
    assert response.status_code == 200
    all_files = response.json["files"]
    assert len(all_files) == 2, "Expected 2 files in the system."
    file_names = [f["file_name"] for f in all_files]
    assert "user1_file.txt" in file_names, "User 1's file not found."
    assert "user2_file.txt" in file_names, "User 2's file not found."