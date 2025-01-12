from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

# Initialize the db instance in your app.py
db = SQLAlchemy()

class EncryptedFile(db.Model):
    __tablename__ = 'encrypted_file'  # Explicitly setting the table name
    
    # UUID as the primary key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(50), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    
    # Setting the default for upload_date to current timestamp
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<EncryptedFile {self.file_name}, uploaded at {self.upload_date}>"

class User(db.Model):
    __tablename__ = 'user'  # Explicitly setting the table name
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<User {self.user_id}>"
