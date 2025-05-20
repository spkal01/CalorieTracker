import os
import time
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

app = Flask(__name__)
# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///calorie_tracker.db'

# App configuration
UPLOAD_FOLDER = './calorie_tracker/static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['SECRET_KEY'] = 'ashdahdadss'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
bcrypt = Bcrypt(app)
# Utility function to check allowed file types
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Utility function to clean up old files
def cleanup_uploads(folder, max_age_seconds):
    now = time.time()
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        if os.path.isfile(file_path) and now - os.path.getmtime(file_path) > max_age_seconds:
            os.remove(file_path)

# Import routes
from calorie_tracker import routes