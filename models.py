from flask_sqlalchemy import SQLAlchemy

# The db instance will be initialized in app.py
db = SQLAlchemy()

# Database Models
class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), nullable=False)
    file_name = db.Column(db.String(120), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
