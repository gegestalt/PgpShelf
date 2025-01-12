from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import gnupg
import os
from models import db, User, EncryptedFile

file_bp = Blueprint('file', __name__)
gpg = gnupg.GPG(gnupghome=os.path.expanduser("~/.gnupg"))
gpg.options = ["--digest-algo", "SHA256"]

@file_bp.route('/generate_keys', methods=['POST'])
@jwt_required()
def generate_keys():
    """Generate PGP keys for a user."""
    current_user = get_jwt_identity()
    passphrase = request.form.get('passphrase')

    if not passphrase:
        return jsonify({"error": "Passphrase is required."}), 400

    # Get user from database
    user = User.query.filter_by(user_id=current_user).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    # Generate key pair
    input_data = gpg.gen_key_input(
        name_real=current_user,
        name_email=f"{current_user}@example.com",
        passphrase=passphrase,
        key_type="RSA",
        key_length=2048
    )
    key = gpg.gen_key(input_data)

    if not key:
        return jsonify({"error": "Failed to generate PGP keys."}), 500

    # Export and save keys
    user.public_key = gpg.export_keys(str(key))
    user.private_key = gpg.export_keys(str(key), True, passphrase=passphrase)
    db.session.commit()

    return jsonify({"message": "PGP keys generated and saved successfully."}), 200

@file_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    """Upload and encrypt a file."""
    current_user = get_jwt_identity()
    if 'file' not in request.files:
        return jsonify({"error": "No file provided."}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "No file selected."}), 400

    # Get user's public key
    user = User.query.filter_by(user_id=current_user).first()
    if not user or not user.public_key:
        return jsonify({"error": "User has no public key."}), 400

    # Import user's public key
    import_result = gpg.import_keys(user.public_key)
    if not import_result.count:
        return jsonify({"error": "Failed to import public key."}), 500

    # Encrypt file content
    encrypted_data = gpg.encrypt(
        file.read(),
        recipients=[f"{current_user}@example.com"],
        always_trust=True
    )

    if not encrypted_data.ok:
        return jsonify({
            "error": "Encryption failed.",
            "details": encrypted_data.status
        }), 500

    # Save encrypted file
    encrypted_file = EncryptedFile(
        user_id=current_user,
        file_name=file.filename,
        encrypted_content=str(encrypted_data).encode('utf-8')
    )
    db.session.add(encrypted_file)
    db.session.commit()

    return jsonify({
        "message": "File uploaded and encrypted successfully.",
        "file_id": encrypted_file.id
    }), 200

@file_bp.route('/files', methods=['GET'])
@jwt_required()
def list_user_files():
    """List files for current user."""
    current_user = get_jwt_identity()
    files = EncryptedFile.query.filter_by(user_id=current_user).all()
    file_list = [{
        "id": f.id,
        "file_name": f.file_name,
        "upload_date": f.upload_date.isoformat(),
    } for f in files]
    return jsonify({"files": file_list}), 200

@file_bp.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt_file():
    """Decrypt a file."""
    current_user = get_jwt_identity()
    file_id = request.form.get('file_id')
    passphrase = request.form.get('passphrase')

    if not file_id or not passphrase:
        return jsonify({"error": "File ID and passphrase are required."}), 400

    # Get file and user
    encrypted_file = EncryptedFile.query.filter_by(
        id=file_id, user_id=current_user
    ).first()
    if not encrypted_file:
        return jsonify({"error": "File not found."}), 404

    user = User.query.filter_by(user_id=current_user).first()
    if not user or not user.private_key:
        return jsonify({"error": "User has no private key."}), 400

    # Import private key
    import_result = gpg.import_keys(user.private_key)
    if not import_result.count:
        return jsonify({"error": "Failed to import private key."}), 500

    # Decrypt file
    decrypted_data = gpg.decrypt(
        encrypted_file.encrypted_content.decode('utf-8'),
        passphrase=passphrase
    )

    if not decrypted_data.ok:
        return jsonify({
            "error": "Decryption failed.",
            "details": decrypted_data.status
        }), 500

    return jsonify({
        "file_name": encrypted_file.file_name,
        "content": str(decrypted_data)
    }), 200

@file_bp.route('/list_all', methods=['GET'])
@jwt_required()
def list_all_files():
    """List all files in the system."""
    files = EncryptedFile.query.all()
    file_list = [{
        "id": f.id,
        "file_name": f.file_name,
        "upload_date": f.upload_date.isoformat(),
        "user_id": f.user_id
    } for f in files]
    return jsonify({"files": file_list}), 200