from flask import Flask, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required
from models import db
import os

# Initialize Flask app and database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# Register routes through init_routes
from routes import init_routes
init_routes(app)

@app.route('/protected')
@jwt_required()
def protected():
    return jsonify({"message": "This is a protected route"}), 200

if __name__ == '__main__':
    app.run(debug=True)
