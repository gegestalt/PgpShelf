import pytest
from flask import Flask
from models import db, User, EncryptedFile
from werkzeug.datastructures import FileStorage
import os
from routes.auth import auth_bp
from routes.file_routes import file_bp
from flask_jwt_extended import JWTManager

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
    
    db.init_app(app)
    JWTManager(app)
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(file_bp, url_prefix='/file')
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_populate_database(client, app):
    """Test populating database with users and their files."""
    # Sample users data
    users = [
        {
            'user_id': 'john_doe',
            'email': 'john@example.com',
            'password': 'password123',
            'passphrase': 'john_secret'
        },
        {
            'user_id': 'jane_smith',
            'email': 'jane@example.com',
            'password': 'password456',
            'passphrase': 'jane_secret'
        },
        {
            'user_id': 'bob_wilson',
            'email': 'bob@example.com',
            'password': 'password789',
            'passphrase': 'bob_secret'
        }
    ]
    
    # Get list of files from upload directory
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'upload')
    files = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))]
    assert len(files) >= 3, "Need at least 3 files in the upload directory"
    
    # Create users and upload their files
    with app.app_context():
        for user, filename in zip(users, files[:3]):  # Take first 3 files
            # Register user
            register_response = client.post('/auth/register', json={
                'user_id': user['user_id'],
                'email': user['email'],
                'password': user['password']
            })
            assert register_response.status_code == 201
            print(f"Created user: {user['user_id']}")
            
            # Login to get token
            login_response = client.post('/auth/login', json={
                'user_id': user['user_id'],
                'password': user['password']
            })
            assert login_response.status_code == 200
            token = login_response.json['access_token']
            
            # Generate keys
            key_response = client.post('/file/generate_keys',
                data={'passphrase': user['passphrase']},
                headers={'Authorization': f'Bearer {token}'})
            assert key_response.status_code == 200
            print(f"Generated keys for: {user['user_id']}")
            
            # Read and upload file
            file_path = os.path.join(upload_dir, filename)
            with open(file_path, 'rb') as f:
                file_content = f.read()
                
                file_storage = FileStorage(
                    stream=open(file_path, 'rb'),
                    filename=filename,
                    content_type='application/octet-stream'
                )
                
                upload_response = client.post('/file/upload',
                    data={'file': file_storage},
                    headers={
                        'Authorization': f'Bearer {token}',
                        'Content-Type': 'multipart/form-data'
                    })
                assert upload_response.status_code == 200
                print(f"Uploaded file {filename} for {user['user_id']}")
                
                # Close the file after upload
                file_storage.stream.close()
        
        # Verify database state
        assert User.query.count() == 3, "Should have 3 users"
        assert EncryptedFile.query.count() == 3, "Should have 3 files"
        
        # Verify each user has their file
        for user in users:
            db_user = User.query.filter_by(user_id=user['user_id']).first()
            assert db_user is not None
            assert db_user.public_key is not None
            assert db_user.private_key is not None
            
            user_files = EncryptedFile.query.filter_by(user_id=user['user_id']).all()
            assert len(user_files) == 1, f"User {user['user_id']} should have exactly one file"

    print("Database populated and verified successfully!") 

def test_file_access_permissions(client, app):
    """Test that users can only access their own files."""
    # Sample users data
    users = [
        {
            'user_id': 'john_doe',
            'email': 'john@example.com',
            'password': 'password123',
            'passphrase': 'john_secret'
        },
        {
            'user_id': 'jane_smith',
            'email': 'jane@example.com',
            'password': 'password456',
            'passphrase': 'jane_secret'
        }
    ]
    
    # Get list of files from upload directory
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'upload')
    files = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))]
    assert len(files) >= 2, "Need at least 2 files in the upload directory"
    
    user_files = {}  # Store file IDs for each user
    
    # Create users and upload their files
    with app.app_context():
        for user, filename in zip(users, files[:2]):  # Take first 2 files
            # Register user
            register_response = client.post('/auth/register', json={
                'user_id': user['user_id'],
                'email': user['email'],
                'password': user['password']
            })
            assert register_response.status_code == 201
            
            # Login to get token
            login_response = client.post('/auth/login', json={
                'user_id': user['user_id'],
                'password': user['password']
            })
            token = login_response.json['access_token']
            
            # Generate keys
            client.post('/file/generate_keys',
                data={'passphrase': user['passphrase']},
                headers={'Authorization': f'Bearer {token}'})
            
            # Upload file
            file_path = os.path.join(upload_dir, filename)
            with open(file_path, 'rb') as f:
                file_storage = FileStorage(
                    stream=open(file_path, 'rb'),
                    filename=filename,
                    content_type='application/octet-stream'
                )
                
                upload_response = client.post('/file/upload',
                    data={'file': file_storage},
                    headers={
                        'Authorization': f'Bearer {token}',
                        'Content-Type': 'multipart/form-data'
                    })
                assert upload_response.status_code == 200
                user_files[user['user_id']] = upload_response.json['file_id']
                file_storage.stream.close()
        
        # Test file access permissions
        for i, user in enumerate(users):
            # Login as current user
            login_response = client.post('/auth/login', json={
                'user_id': user['user_id'],
                'password': user['password']
            })
            token = login_response.json['access_token']
            
            # Try to access own file
            own_file_response = client.post('/file/decrypt/info',
                data={'file_id': user_files[user['user_id']]},
                headers={'Authorization': f'Bearer {token}'})
            assert own_file_response.status_code == 200, f"User cannot access their own file"
            
            # Try to access other user's file
            other_user = users[(i + 1) % len(users)]
            other_file_response = client.post('/file/decrypt/info',
                data={'file_id': user_files[other_user['user_id']]},
                headers={'Authorization': f'Bearer {token}'})
            assert other_file_response.status_code == 403, f"User should not be able to access other user's file"
            
            # Try to download other user's file
            other_file_download = client.post(
                f"/file/decrypt/download/{user_files[other_user['user_id']]}",
                data={'passphrase': user['passphrase']},
                headers={'Authorization': f'Bearer {token}'})
            assert other_file_download.status_code == 403, f"User should not be able to download other user's file"
            
            # Verify successful download of own file
            own_file_download = client.post(
                f"/file/decrypt/download/{user_files[user['user_id']]}",
                data={'passphrase': user['passphrase']},
                headers={'Authorization': f'Bearer {token}'})
            assert own_file_download.status_code == 200, f"User should be able to download their own file"

    print("File access permissions verified successfully!") 

def test_file_upload_with_hash(client, app):
    """Test file upload includes correct hash value."""
    token = get_auth_token(client)
    
    # Generate keys first
    client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})

    # Upload file
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'upload')
    test_file = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))][0]
    file_path = os.path.join(upload_dir, test_file)
    
    with open(file_path, 'rb') as f:
        file_storage = FileStorage(
            stream=open(file_path, 'rb'),
            filename=test_file,
            content_type='application/octet-stream'
        )
        
        upload_response = client.post('/file/upload',
            data={'file': file_storage},
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'multipart/form-data'
            })
        file_storage.stream.close()
        
        assert upload_response.status_code == 200
        assert 'file_id' in upload_response.json
        assert 'content_hash' in upload_response.json
        
        # Verify hash exists in database using modern SQLAlchemy style
        with app.app_context():
            file = db.session.get(EncryptedFile, upload_response.json['file_id'])
            assert file.content_hash == upload_response.json['content_hash']
            assert len(file.content_hash) == 64  # SHA-256 hash length

def test_list_files_with_hash(client, app):
    """Test that file listing includes hash values."""
    token = get_auth_token(client)
    
    # Generate keys and upload file
    client.post('/file/generate_keys', 
        data={"passphrase": "test_passphrase"},
        headers={'Authorization': f'Bearer {token}'})

    # Upload a test file
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'upload')
    test_file = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))][0]
    file_path = os.path.join(upload_dir, test_file)
    
    with open(file_path, 'rb') as f:
        file_storage = FileStorage(
            stream=open(file_path, 'rb'),
            filename=test_file,
            content_type='application/octet-stream'
        )
        
        upload_response = client.post('/file/upload',
            data={'file': file_storage},
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'multipart/form-data'
            })
        file_storage.stream.close()

    # Get file listing
    list_response = client.get('/file/files',
        headers={'Authorization': f'Bearer {token}'})
    
    assert list_response.status_code == 200
    files = list_response.json['files']
    assert len(files) > 0
    
    # Verify hash is included in listing
    for file in files:
        assert 'content_hash' in file
        assert len(file['content_hash']) == 64 

def get_auth_token(client, user_id="testuser", password="testpassword", email="test@example.com"):
    """Helper function to register a user and get auth token."""
    # Register user
    register_response = client.post('/auth/register', json={
        'user_id': user_id,
        'email': email,
        'password': password
    })
    
    # Login to get token
    login_response = client.post('/auth/login', json={
        'user_id': user_id,
        'password': password
    })
    return login_response.json['access_token'] 