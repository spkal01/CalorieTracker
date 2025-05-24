import os

OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 'yes']
MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() in ['true', '1', 'yes']
MAIL_DEFAULT_SENDER = (
    os.environ.get('MAIL_DEFAULT_SENDER_NAME', 'Calorie Tracker'),
    os.environ.get('MAIL_DEFAULT_SENDER_EMAIL', MAIL_USERNAME)
)
SECRET_KEY = os.environ.get('SECRET_KEY', '')
SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', 'secret-reset-salty')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', SECRET_KEY)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'adminlogin&')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', MAIL_USERNAME)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
