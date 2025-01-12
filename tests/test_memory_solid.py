import pytest
from werkzeug.datastructures import FileStorage
from io import BytesIO
from app import app, db
from models import User, EncryptedFile
from sqlalchemy import inspect  # Import inspect to check table names

@pytest.fixture
def client():
    """Set up the test client and mock database session."""
    app.testing = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory DB for tests
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
    app.config['SQLALCHEMY_MIGRATE_REPO'] = None  # Disable Alembic migrations for tests

    # Disable Alembic migration logic completely
    with app.app_context():
        # Drop all tables, including Alembic's version table, and recreate them
        db.drop_all()
        db.create_all()

    # Initialize the test client
    client = app.test_client()

    yield client

    # Tear down: Drop all tables after tests to ensure a clean slate
    with app.app_context():
        db.drop_all()


def test_schema_initialized(client):
    """Ensure the in-memory database schema is initialized properly."""
    with app.app_context():
        # Directly use the inspect module from SQLAlchemy (no need for Alembic)
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Ignore 'alembic_version' table in the comparison
        expected_tables = {"user", "encrypted_file"}
        
        # Ensure only the expected tables exist
        assert set(tables) == expected_tables, f"Tables not initialized correctly, found: {tables}"


def test_generate_keys(client):
    """Test key pair generation for a user."""
    user_id = "test_user"
    passphrase = "test_passphrase"

    with app.app_context():
        response = client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})

        assert response.status_code == 200
        assert "PGP keys generated and saved successfully." in response.json["message"]

        # Verify user in the database
        user = User.query.filter_by(user_id=user_id).first()
        assert user is not None, "User not found in the database."
        assert user.public_key is not None, "Public key not saved."
        assert user.private_key is not None, "Private key not saved."


def test_upload_file(client):
    """Test file upload for a user."""
    user_id = "test_user"
    passphrase = "test_passphrase"

    # Generate keys first
    client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})

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

        # Verify the file in the database
        uploaded_file = EncryptedFile.query.filter_by(user_id=user_id).first()
        assert uploaded_file is not None, "File not found in the database after upload."


def test_list_user_files(client):
    """Test listing files for a specific user."""
    user_id = "test_user"
    passphrase = "test_passphrase"

    client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})

    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )
    client.post('/upload', data={"user_id": user_id, "file": file_storage}, content_type='multipart/form-data')

    response = client.get(f'/files?user_id={user_id}')
    assert response.status_code == 200

    file_list = response.json["files"]
    assert len(file_list) == 1
    assert file_list[0]["uploaded_by"] == user_id


def test_decrypt_file(client):
    """Test decrypting an uploaded file."""
    user_id = "test_user"
    passphrase = "test_passphrase"

    client.post('/generate_keys', data={"user_id": user_id, "passphrase": passphrase})

    file_data = b"This is a test file for encryption and decryption."
    file_storage = FileStorage(
        stream=BytesIO(file_data),
        filename="test_file.txt",
        content_type="text/plain"
    )
    upload_response = client.post('/upload', data={"user_id": user_id, "file": file_storage}, content_type='multipart/form-data')

    file_id = upload_response.json.get("file_id")
    response = client.post('/decrypt', data={"user_id": user_id, "file_id": file_id, "passphrase": passphrase})
    assert response.status_code == 200
    assert response.json["content"] == file_data.decode("utf-8")
