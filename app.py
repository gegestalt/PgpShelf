from flask import Flask
from flask_migrate import Migrate
from models import db
import os

# Initialize Flask app and database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_data.db'  # Update as needed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)  # Add Flask-Migrate here

from routes import init_routes
init_routes(app)

if __name__ == '__main__':
    app.run(debug=True)
