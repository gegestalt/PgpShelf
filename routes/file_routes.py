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

    # Get user's public key using modern query style
    user = db.session.scalar(
        db.select(User).filter_by(user_id=current_user)
    )
    if not user or not user.public_key:
        return jsonify({"error": "User keys not found."}), 404

    try:
        # Import public key
        import_result = gpg.import_keys(user.public_key)
        if not import_result.fingerprints:
            return jsonify({"error": "Failed to import public key."}), 500

        # Encrypt file content
        file_content = file.read()
        encrypted_data = gpg.encrypt(
            file_content,
            import_result.fingerprints[0],
            always_trust=True
        )

        if not encrypted_data.ok:
            return jsonify({"error": "Encryption failed."}), 500

        # Save encrypted file
        encrypted_file = EncryptedFile(
            user_id=current_user,
            file_name=file.filename,
            encrypted_content=str(encrypted_data).encode()
        )
        db.session.add(encrypted_file)
        db.session.commit()

        return jsonify({
            "message": "File uploaded and encrypted successfully.",
            "file_id": encrypted_file.id
        }), 200

    except Exception as e:
        return jsonify({"error": f"Upload error: {str(e)}"}), 500

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
    """Decrypt a file for an authorized user."""
    current_user = get_jwt_identity()
    file_id = request.form.get('file_id')
    passphrase = request.form.get('passphrase')

    if not file_id or not passphrase:
        return jsonify({"error": "File ID and passphrase are required."}), 400

    # Use db.session.get() instead of query.get()
    encrypted_file = db.session.get(EncryptedFile, file_id)
    if not encrypted_file:
        return jsonify({"error": "File not found."}), 404

    # Then check if user owns the file
    if encrypted_file.user_id != current_user:
        return jsonify({"error": "You are not authorized to decrypt this file."}), 403

    # Get user's private key using modern query style
    user = db.session.scalar(
        db.select(User).filter_by(user_id=current_user)
    )
    if not user or not user.private_key:
        return jsonify({"error": "User keys not found."}), 404

    try:
        # Import private key
        import_result = gpg.import_keys(user.private_key)
        if not import_result.fingerprints:
            return jsonify({"error": "Failed to import private key."}), 500

        # Decrypt the file
        decrypted_data = gpg.decrypt(
            encrypted_file.encrypted_content,
            passphrase=passphrase
        )

        if not decrypted_data.ok:
            return jsonify({"error": "Decryption failed."}), 400

        return jsonify({
            "file_name": encrypted_file.file_name,
            "content": str(decrypted_data)
        }), 200

    except Exception as e:
        return jsonify({"error": f"Decryption error: {str(e)}"}), 500

@file_bp.route('/list_all', methods=['GET'])
@jwt_required()
def list_all_files():
    """List all files for the current user."""
    try:
        # Use modern SQLAlchemy style
        files = db.session.scalars(
            db.select(EncryptedFile)
        ).all()
        
        return jsonify({
            "files": [{
                "id": str(file.id),
                "file_name": file.file_name,
                "upload_date": file.upload_date.isoformat()
            } for file in files]
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list files: {str(e)}"}), 500