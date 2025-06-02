import os

# Read the comma-separated string of API keys from the environment variable
OPENAI_API_KEYS_STR = os.environ.get(
    'OPENAI_API_KEYS_STR', 
    ''
)

# Split the string into a list of keys
# Filter out any empty strings that might result from trailing commas or multiple commas
OPENAI_API_KEYS = [key.strip() for key in OPENAI_API_KEYS_STR.split(',') if key.strip()]

# Fallback to a single key if parsing fails or results in an empty list, using the old single key variable if it exists
# This provides a smoother transition if you previously used OPENAI_API_KEY
if not OPENAI_API_KEYS:
    single_key_fallback = os.environ.get('OPENAI_API_KEY','')
    if single_key_fallback:
        OPENAI_API_KEYS = [single_key_fallback.strip()]
    else:
        # If no keys are found at all, you might want to log an error or raise one,
        # depending on how critical these keys are for your app's startup.
        # For now, we'll leave it as potentially empty, and your route logic should handle it.
        print("Warning: No OpenAI API keys found in environment variables.")
        OPENAI_API_KEYS = []
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
SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///calorie_tracker.db')

# Push notification configuration
VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY', '')
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY', '')
VAPID_CLAIM_EMAIL = os.environ.get('VAPID_CLAIM_EMAIL', MAIL_USERNAME or 'contact@calorietracker.example.com')
