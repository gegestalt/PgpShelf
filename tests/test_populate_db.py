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