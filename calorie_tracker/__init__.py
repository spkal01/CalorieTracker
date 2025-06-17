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
from flask_dance.contrib.google import make_google_blueprint
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect
from celery import Celery
from celery import shared_task
from celery.schedules import crontab 

# Create Flask app and trust proxy headers (Render)
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI

# App configuration
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static', 'uploads'))
if not os.path.exists(UPLOAD_FOLDER):
    try:
        os.makedirs(UPLOAD_FOLDER)
    except OSError as e:
        print(f"Error creating upload folder: {e}")
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'heic'}
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = config.MAIL_USE_SSL
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_DEFAULT_SENDER
app.config['SERVER_NAME'] = config.SERVER_NAME
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Push notification configuration
app.config['VAPID_PUBLIC_KEY'] = os.environ.get('VAPID_PUBLIC_KEY', config.VAPID_PUBLIC_KEY)
app.config['VAPID_PRIVATE_KEY'] = os.environ.get('VAPID_PRIVATE_KEY', config.VAPID_PRIVATE_KEY)
app.config['VAPID_CLAIM_EMAIL'] = os.environ.get('VAPID_CLAIM_EMAIL', config.VAPID_CLAIM_EMAIL)

# Ensure secure cookies and proxy support for OAuth on production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['PREFERRED_URL_SCHEME'] = "https"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = "Lax"

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)  # Initialize CSRFProtect

# --- Celery Configuration ---
celery = Celery(
    app.import_name, 
    broker=config.CELERY_BROKER_URL,
    backend=config.CELERY_BROKER_URL,
    include=['calorie_tracker.routes']
)
celery.conf.update(app.config)

class ContextTask(celery.Task):
    def __call__(self, *args, **kwargs):
        with app.app_context():
            return self.run(*args, **kwargs)

celery.Task = ContextTask # Set the default Task class for Celery

# --- Celery Beat Schedule ---
celery.conf.beat_schedule = {
    'schedule-all-meal-reminders-daily': {
        'task': 'calorie_tracker.routes.schedule_meal_reminders',
        'schedule': crontab(hour=1, minute=0),  # Runs daily at 1:00 AM
        # You can adjust the time as needed, e.g., crontab(minute='*/30') for every 30 mins for testing
    },
}
celery.conf.timezone = 'UTC' 


# Configure Google OAuth blueprint (uses /login/google and /login/google/authorized)
google_bp = make_google_blueprint(
    client_id=config.GOOGLE_CLIENT_ID,
    client_secret=config.GOOGLE_CLIENT_SECRET,
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
)  # use OIDC scopes to match Google's current API
app.register_blueprint(google_bp, url_prefix='/login')

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

# Register push notification blueprint
from calorie_tracker.push_routes import push_notification_bp
app.register_blueprint(push_notification_bp)

admin = Admin(app, name='Calorie Tracker Admin', template_mode='bootstrap4', index_view=AdminView())
admin.add_view(AdminUser(User, db.session, name='Users'))
admin.add_view(FileAdminView(UPLOAD_FOLDER, name='Uploads'))
#with app.app_context():
#    create_admin_user()
# Cleanup old files every 24 hours
cleanup_uploads(UPLOAD_FOLDER, max_age_seconds=24*60*60)
