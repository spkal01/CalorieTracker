web: gunicorn calorie_tracker:app
worker: celery -A calorie_tracker.celery worker --loglevel=info
beat: celery -A calorie_tracker.celery beat --loglevel=info