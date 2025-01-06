from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from flask_sqlalchemy import SQLAlchemy
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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

def generate_key_pair():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_file(data: bytes, public_key):
    """Encrypt the file data with the user's public key."""
    encrypted = public_key.encrypt(
        data,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return encrypted

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({"error": "User ID is required."}), 400

    # Check if the user already exists
    existing_user = User.query.filter_by(user_id=user_id).first()
    if existing_user:
        return jsonify({"error": "User already exists with generated keys."}), 400

    # Generate new keys
    private_key, public_key = generate_key_pair()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the new user with keys in the database
    new_user = User(
        user_id=user_id,
        public_key=public_key_pem.decode('utf-8'),
        private_key=private_key_pem.decode('utf-8')
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Keys generated and saved successfully."}), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({"error": "User ID is required."}), 400

    # Retrieve user and public key from the database
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    public_key = serialization.load_pem_public_key(user.public_key.encode('utf-8'))

    # Check if a file is uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    uploaded_file = request.files['file']
    file_data = uploaded_file.read()

    # Encrypt the file
    encrypted_data = encrypt_file(file_data, public_key)

    encrypted_file = EncryptedFile(
        user_id=user_id,
        file_name=uploaded_file.filename,
        encrypted_content=encrypted_data
    )
    db.session.add(encrypted_file)
    db.session.commit()

    return jsonify({
        "message": "File uploaded and encrypted successfully.",
        "file_id": encrypted_file.id  # Include file_id in the response
    }), 200

@app.route('/files', methods=['GET'])
def list_files():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "User ID is required."}), 400

    files = EncryptedFile.query.filter_by(user_id=user_id).all()
    if not files:
        return jsonify({"message": "No files found for this user."}), 200

    file_list = [{"file_name": f.file_name, "id": f.id} for f in files]
    return jsonify({"files": file_list}), 200


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """Endpoint to decrypt a file."""
    # Retrieve parameters from the request
    user_id = request.form.get('user_id')
    file_id = request.form.get('file_id')

    # Validate the input parameters
    if not user_id or not file_id:
        print("Debug: Missing user_id or file_id")
        return jsonify({"error": "User ID and File ID are required."}), 400

    # Retrieve the user from the database
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        print(f"Debug: User not found for user_id={user_id}")
        return jsonify({"error": "User not found."}), 404

    # Retrieve the file from the database
    encrypted_file = EncryptedFile.query.filter_by(id=file_id, user_id=user_id).first()
    if not encrypted_file:
        print(f"Debug: File not found or unauthorized access for file_id={file_id}, user_id={user_id}")
        return jsonify({"error": "File not found or does not belong to the user."}), 404

    # Load the user's private key
    try:
        private_key = serialization.load_pem_private_key(
            user.private_key.encode('utf-8'),
            password=None
        )
        print("Debug: Private key successfully loaded")
    except Exception as e:
        print(f"Debug: Failed to load private key. Error: {e}")
        return jsonify({"error": "Failed to load private key.", "details": str(e)}), 500

    # Decrypt the file content
    try:
        decrypted_content = private_key.decrypt(
            encrypted_file.encrypted_content,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
        print("Debug: File decrypted successfully")
    except Exception as e:
        print(f"Debug: Decryption failed. Error: {e}")
        return jsonify({"error": "Decryption failed.", "details": str(e)}), 500

    return jsonify({
        "file_name": encrypted_file.file_name,
        "content": decrypted_content.decode('utf-8')
    }), 200

@app.route('/list', methods=['GET'])
def list_all_files():
    """List all uploaded files with their encrypted content."""
    files = EncryptedFile.query.all()
    if not files:
        return jsonify({"files": []}), 200  # Return an empty list if no files exist.

    file_list = [
        {
            "file_name": f.file_name,
            "user_id": f.user_id,
            "encrypted_content": base64.b64encode(f.encrypted_content).decode('utf-8')
        }
        for f in files
    ]
    return jsonify({"files": file_list}), 200


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
