from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib

# Initialize the db instance in your app.py
db = SQLAlchemy()

class EncryptedFile(db.Model):
    __tablename__ = 'encrypted_file'  # Explicitly setting the table name
    
    # UUID as the primary key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(50), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    content_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hash
    
    # Setting the default for upload_date to current timestamp
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def calculate_hash(self):
        """Calculate SHA-256 hash of encrypted content."""
        return hashlib.sha256(self.encrypted_content).hexdigest()

    def __init__(self, **kwargs):
        super(EncryptedFile, self).__init__(**kwargs)
        self.content_hash = self.calculate_hash()

    def __repr__(self):
        return f"<EncryptedFile {self.file_name}, uploaded at {self.upload_date}>"

class User(db.Model):
    __tablename__ = 'user'  # Explicitly setting the table name
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.user_id}>"
