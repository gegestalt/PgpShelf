from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import gnupg
import os
import base64
from models import db, User, EncryptedFile

# Initialize Flask app and database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize GPG
gpg = gnupg.GPG(gnupghome=os.path.expanduser("~/.gnupg"))


@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    """Generate PGP keys for a user."""
    user_id = request.form.get('user_id')
    passphrase = request.form.get('passphrase')

    if not user_id or not passphrase:
        return jsonify({"error": "User ID and passphrase are required."}), 400

    # Check if the user already exists
    if User.query.filter_by(user_id=user_id).first():
        return jsonify({"error": "User already exists with generated keys."}), 400

    # Generate PGP key pair with the passphrase
    input_data = gpg.gen_key_input(
        name_email=f"{user_id}@example.com",
        passphrase=passphrase
    )
    key = gpg.gen_key(input_data)

    if not key:
        return jsonify({"error": "Failed to generate PGP keys."}), 500

    # Export public and private keys
    public_key = gpg.export_keys(str(key))
    private_key = gpg.export_keys(str(key), True, passphrase=passphrase)

    # Save keys and user info in the database
    new_user = User(
        user_id=user_id,
        public_key=public_key,
        private_key=private_key
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "PGP keys generated and saved successfully."}), 200


@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload and encrypt a file for a user."""
    user_id = request.form.get('user_id')

    if not user_id:
        return jsonify({"error": "User ID is required."}), 400

    # Retrieve the user from the database
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    # Check if a file is uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    uploaded_file = request.files['file']
    file_data = uploaded_file.read()

    # Encrypt the file using the user's public key
    encrypted_data = gpg.encrypt(file_data, user.user_id)
    if not encrypted_data.ok:
        return jsonify({"error": "Encryption failed.", "details": encrypted_data.status}), 500

    # Save encrypted content to the database
    encrypted_file = EncryptedFile(
        user_id=user_id,
        file_name=uploaded_file.filename,
        encrypted_content=str(encrypted_data).encode('utf-8')
    )
    db.session.add(encrypted_file)
    db.session.commit()

    return jsonify({
        "message": "File uploaded and encrypted successfully.",
        "file_id": encrypted_file.id
    }), 200


@app.route('/files', methods=['GET'])
def list_user_files():
    """List all files uploaded by a specific user."""
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({"error": "User ID is required."}), 400

    # Retrieve files for the user
    files = EncryptedFile.query.filter_by(user_id=user_id).all()
    if not files:
        return jsonify({"message": "No files found for this user."}), 200

    file_list = [{"file_name": f.file_name, "id": f.id} for f in files]
    return jsonify({"files": file_list}), 200


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """Decrypt an uploaded file."""
    user_id = request.form.get('user_id')
    file_id = request.form.get('file_id')
    passphrase = request.form.get('passphrase')

    if not user_id or not file_id or not passphrase:
        return jsonify({"error": "User ID, File ID, and passphrase are required."}), 400

    # Retrieve the user from the database
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    # Retrieve the file from the database
    encrypted_file = EncryptedFile.query.filter_by(id=file_id, user_id=user_id).first()
    if not encrypted_file:
        return jsonify({"error": "File not found or unauthorized access."}), 404

    # Decrypt the file using the user's private key
    decrypted_data = gpg.decrypt(
        encrypted_file.encrypted_content.decode('utf-8'),
        passphrase=passphrase
    )
    if not decrypted_data.ok:
        return jsonify({"error": "Decryption failed.", "details": decrypted_data.status}), 500

    return jsonify({
        "file_name": encrypted_file.file_name,
        "content": str(decrypted_data)
    }), 200


@app.route('/list_all', methods=['GET'])
def list_all_files():
    """List all files with encrypted content."""
    files = EncryptedFile.query.all()
    if not files:
        return jsonify({"files": []}), 200

    file_list = [
        {
            "file_name": f.file_name,
            "user_id": f.user_id,
            "encrypted_content": base64.b64encode(f.encrypted_content).decode('utf-8')
        }
        for f in files
    ]
    return jsonify({"files": file_list}), 200


@app.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    """Download an encrypted file."""
    encrypted_file = EncryptedFile.query.filter_by(id=file_id).first()
    if not encrypted_file:
        return jsonify({"error": "File not found."}), 404

    return jsonify({
        "file_name": encrypted_file.file_name,
        "encrypted_content": base64.b64encode(encrypted_file.encrypted_content).decode('utf-8')
    }), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
