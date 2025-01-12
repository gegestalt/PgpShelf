# routes/__init__.py
from flask import Flask
from .auth import auth_bp
from .file_routes import file_bp

def init_routes(app: Flask):
    """Initialize all blueprint routes"""
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(file_bp, url_prefix='/file')
