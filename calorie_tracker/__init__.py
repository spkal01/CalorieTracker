import os
import time
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from calorie_tracker import config
from flask_admin import Admin
from flask_migrate import Migrate

app = Flask(__name__)
# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///calorie_tracker.db'

# App configuration
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static', 'uploads'))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
bcrypt = Bcrypt(app)
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = config.MAIL_USE_SSL
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_DEFAULT_SENDER

mail = Mail(app)
migrate = Migrate(app, db)
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
from calorie_tracker.routes import create_admin_user
from calorie_tracker.models import User
from calorie_tracker.admin_views import AdminUser, FileAdminView, AdminView
admin = Admin(app, name='Calorie Tracker Admin', template_mode='bootstrap3', index_view=AdminView())
admin.add_view(AdminUser(User, db.session, name='Users'))
admin.add_view(FileAdminView(UPLOAD_FOLDER, name='Uploads'))
with app.app_context():
    create_admin_user()
# Cleanup old files every 24 hours
cleanup_uploads(UPLOAD_FOLDER, max_age_seconds=24*60*60)