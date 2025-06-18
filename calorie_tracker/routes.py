import hashlib
import os
import re
import random
import base64
import cv2
import secrets
import json
import pytz
from datetime import datetime as dt, timedelta 
import threading
from flask import (
    flash, render_template, request, redirect, url_for, session, jsonify, send_from_directory, g
)
from werkzeug.utils import secure_filename
from pywebpush import webpush, WebPushException
# Import Pillow and pillow-heif
from PIL import Image
import pillow_heif

from calorie_tracker import (
    app, allowed_file, cleanup_uploads, config, db, bcrypt, login_manager, mail, celery, shared_task
)

from calorie_tracker.models import (
    User, FoodItem, SavedCalories,
    UserDietDay, Meal, MealItem, DayOfWeekEnum, MealTypeEnum, PushSubscription,
)

from flask_login import (
    login_user, logout_user, login_required, current_user
)
from flask_mail import Message

from itsdangerous import URLSafeTimedSerializer
from email_validator import validate_email, EmailNotValidError
import openai
from flask_dance.contrib.google import google
from flask_dance.consumer import oauth_authorized
from calorie_tracker import google_bp


# Ensure pillow-heif is registered (usually automatic, but can be explicit)
pillow_heif.register_heif_opener()

# Store the current key index, start with the primary key
current_api_key_index = 0
# Store the time of the last reset
last_key_reset_time = None

def call_openai_api_with_fallback(**kwargs):
    global current_api_key_index, last_key_reset_time
    keys = getattr(config, 'OPENAI_API_KEYS', [])
    if not keys:
        app.logger.error("OPENAI_API_KEYS not configured or empty in config.py")
        raise ValueError("OPENAI_API_KEYS not configured or empty in config.py")

    now = dt.now()

    # Check if it's time to reset the API key index
    if last_key_reset_time is None:
        last_key_reset_time = now
        app.logger.info(f"Initializing last_key_reset_time to {last_key_reset_time}")
    elif now - last_key_reset_time >= timedelta(hours=24):
        current_api_key_index = 0
        last_key_reset_time = now
        app.logger.info(f"Reset OpenAI API key index to 0. New reset time: {last_key_reset_time}")

    num_keys = len(keys)
    
    for i in range(num_keys):
        key_to_try_index = (current_api_key_index + i) % num_keys
        api_key_to_use = keys[key_to_try_index]
        
        if not api_key_to_use: # Skip if a key is an empty string
            app.logger.warning(f"Skipping empty API key at index {key_to_try_index}.")
            continue

        try:
            app.logger.info(f"Attempting OpenAI API call with key index {key_to_try_index}")
            
            # Create a new client instance for each attempt with the specific API key
            client = openai.OpenAI(api_key=api_key_to_use)
            response = client.chat.completions.create(**kwargs) # Use the new client instance
            
            current_api_key_index = key_to_try_index
            app.logger.info(f"OpenAI API call successful with key index {key_to_try_index}.")
            return response
        except openai.APIConnectionError as e:
            app.logger.warning(f"OpenAI APIConnectionError with key index {key_to_try_index}: {e}")
        except openai.RateLimitError as e:
            app.logger.warning(f"OpenAI RateLimitError with key index {key_to_try_index}: {e}. Trying next key.")
        except openai.AuthenticationError as e:
            app.logger.error(f"OpenAI AuthenticationError with key index {key_to_try_index}: {e}. This key is invalid. Trying next key.")
        except openai.APIStatusError as e:
            app.logger.error(f"OpenAI APIStatusError with key index {key_to_try_index} (Status: {e.status_code}): {e.message}")
        except Exception as e:
            app.logger.error(f"Unexpected error during OpenAI API call with key index {key_to_try_index}: {e}")
            if i == num_keys - 1: # If this was the last key
                raise e 

    app.logger.error("All OpenAI API keys failed.")
    raise Exception("All OpenAI API keys failed after trying all available keys.")

def read_image_base64(image_path_or_bytes, is_bytes=False, original_extension=".jpg"):
    if is_bytes:
        return base64.b64encode(image_path_or_bytes).decode('utf-8')
    else:
        with open(image_path_or_bytes, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')

@app.before_request
def require_login():
    public_routes = [
        'login', 'signup', 'static', 'signup_verify', 'signup_email',
        'forgot_password', 'reset_password', 'landing',
        'login_google', 'google.login', 'google.authorized',
        'serve_sw', 'offline_page', "serve_assetlinks"
    ]
    if not current_user.is_authenticated and request.endpoint not in public_routes:
        return redirect(url_for('landing'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

def password_strength_score(password):
    import re
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^A-Za-z0-9]', password):
        score += 1
    return score

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('login/signup_step1.html')
        score = password_strength_score(password)
        if score < 3:
            flash('Password must be at least medium strength (8+ chars, upper, lower, digit or special char).', 'error')
            return render_template('login/signup_step1.html')
        if score == 3:
            flash('Warning: Medium strength password. Consider using a stronger password for better security.', 'warning')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('login/signup_step1.html')
        # Store in session and go to step 2
        session['signup_username'] = username
        session['signup_password'] = password
        return redirect(url_for('signup_email'))
    return render_template('login/signup_step1.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            email_info = validate_email(email, check_deliverability=False)
            email = email_info.normalized
        except EmailNotValidError as e:
            flash(str(e), 'error')
            return render_template('login/forgot_password.html')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            email_body = (
                f"Hello,\n\n"
                f"To reset your password, click the link below:\n\n"
                f"{reset_url}\n\n"
                f"If you did not request this, please ignore this email.\n\n"
                f"Best regards,\n"
                f"The CalorieTracker Team"
            )
            send_email('Your CalorieTracker Password Reset Link', email, email_body)
            flash('A password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'error')
    return render_template('login/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('login/reset_password.html', token=token)
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            flash('Your password has been reset. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'error')
    return render_template('login/reset_password.html', token=token)

@app.route('/signup/email', methods=['GET', 'POST'])
def signup_email():
    if 'signup_username' not in session or 'signup_password' not in session:
        return redirect(url_for('signup'))
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            email_info = validate_email(email, check_deliverability=True)
            email = email_info.normalized
        except EmailNotValidError as e:
            flash(str(e), 'error')
            return render_template('login/signup_step2.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('login/signup_step2.html')
        # Generate and "send" verification code
        code = str(random.randint(100000, 999999))
        session['signup_email'] = email
        session['signup_code'] = code
        email_body = (
            f"Hello,\n\n"
            f"Thank you for signing up for CalorieTracker!\n\n"
            f"Your verification code is:\n\n"
            f"    {code}\n\n"
            f"Please enter this code to complete your registration.\n\n"
            f"If you did not request this, please ignore this email.\n\n"
            f"Best regards,\n"
            f"The CalorieTracker Team"
        )
        send_email('Your CalorieTracker Verification Code', email, email_body)
        return redirect(url_for('signup_verify'))
    return render_template('login/signup_step2.html')

@app.route('/signup/verify', methods=['GET', 'POST'])
def signup_verify():
    if 'signup_email' not in session or 'signup_code' not in session:
        return redirect(url_for('signup'))
    if request.method == 'POST':
        code = request.form.get('code')
        if code == session.get('signup_code'):
            # Create user
            username = session['signup_username']
            password = session['signup_password']
            email = session['signup_email']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            # Clear session
            session.pop('signup_username', None)
            session.pop('signup_password', None)
            session.pop('signup_email', None)
            session.pop('signup_code', None)
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code.', 'error')
    return render_template('login/signup_step3.html')

@app.route('/')
@login_required
def index():
    custom_calories = request.args.get('calories', default=0, type=int)
    food_name = request.args.get('food_name', default='', type=str)
    if custom_calories and food_name:
        push_data(custom_calories, food_name=food_name)
        return redirect(url_for('saved'))
    calorie_goal = current_user.daily_calorie_goal if current_user.daily_calorie_goal else 2000
    calories_eaten = get_saved_data()[0]['total_calories_today'] if get_saved_data() else 0
    return render_template('dashboard.html', year=dt.now().year, calorie_goal=calorie_goal, calories_eaten = calories_eaten, calories_remaining=(calorie_goal - calories_eaten))

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/saved', methods=['GET', 'POST'])
@login_required
def saved():
    if request.method == 'POST':
        date = request.form.get('date')
        food_name = request.form.get('food_name')
        food_calories_str = request.form.get('food_calories')
        if date and food_name and food_calories_str:
            try:
                food_calories = int(food_calories_str)
                entry = SavedCalories.query.filter_by(date=date, user_id=current_user.id).first()
                if not entry:
                    entry = SavedCalories(date=date, user_id=current_user.id)
                    db.session.add(entry)
                    # Commit here if you need entry.id immediately, or before adding FoodItem
                    db.session.flush() # Makes entry.id available if it's new

                food = FoodItem(saved_calories_id=entry.id, name=food_name, calories=food_calories)
                db.session.add(food)
                db.session.commit()
                flash('Food item added successfully!', 'success')
                check_and_send_goal_achievement_notification(current_user, food_calories)
            except ValueError:
                flash('Invalid calorie amount.', 'error')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error adding food item in /saved: {e}")
                flash('An error occurred while adding the food item.', 'error')
        else:
            flash('Please provide date, food name, and food calories.', 'error')
    saved_data = get_saved_data()
    edit_date = request.args.get('edit')
    return render_template('saved.html', saved_data=saved_data, edit_date=edit_date)


@app.route('/custom_calories', methods=['GET', 'POST'])
@login_required
def custom_calories():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(url_for('custom_calories'))
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('custom_calories'))
        
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            _, extension = os.path.splitext(original_filename)
            extension = extension.lower() # Ensure consistent case

            if not extension:
                flash('File has no extension.', 'error')
                return redirect(url_for('custom_calories'))

            dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
            
            # For HEIC, we'll convert to PNG for processing and storage consistency
            # The final saved file will be PNG if original was HEIC
            processing_extension = ".png" if extension == ".heic" else extension
            new_filename = dt_now + processing_extension
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)

            img_for_cv = None
            image_bytes_for_base64 = None
            mime_type_for_openai = "image/png" # Default to PNG after conversion

            try:
                if extension == ".heic":
                    # Read HEIC using pillow-heif
                    heif_file = pillow_heif.read_heif(file)
                    img_pil = Image.frombytes(
                        heif_file.mode,
                        heif_file.size,
                        heif_file.data,
                        "raw",
                    )
                    # Convert PIL image to an OpenCV compatible format (NumPy array)
                    # And save as PNG
                    img_pil.save(file_path, format="PNG") # Save the converted file as PNG
                    
                    # For OpenCV processing if still needed (though we might not need cv2.imread anymore)
                    # img_for_cv = cv2.cvtColor(np.array(img_pil), cv2.COLOR_RGB2BGR) # If you need BGR for OpenCV
                    
                    # For base64 encoding, get PNG bytes
                    with open(file_path, "rb") as f_png:
                        image_bytes_for_base64 = f_png.read()
                    mime_type_for_openai = "image/png"

                else: # For JPG, PNG, JPEG
                    file.save(file_path)
                    # img_for_cv = cv2.imread(file_path) # If you still need OpenCV object
                    with open(file_path, "rb") as f_img:
                        image_bytes_for_base64 = f_img.read()
                    
                    if extension == ".png":
                        mime_type_for_openai = "image/png"
                    elif extension in [".jpg", ".jpeg"]:
                        mime_type_for_openai = "image/jpeg"
                    else: # Fallback, though allowed_extensions should limit this
                        mime_type_for_openai = "application/octet-stream"


                if image_bytes_for_base64:
                    image_base64 = base64.b64encode(image_bytes_for_base64).decode('utf-8')

                    # Prepare GPT-4 Vision request
                    response = call_openai_api_with_fallback( 
                        model="gpt-4o-mini", 
                        messages=[ 
                            {
                                "role": "user",
                                "content": [
                                    {"type": "text", "text": "Please analyze this image and provide the calorie count. The first integer in the response should be the calorie count. You should always start with the phrase 'The food item you uploaded is name' Replace name with the actual food name."},
                                    {"type": "text", "text": "Please provide the calorie count in kcal."},
                                    {"type": "text", "text": "Dont provide any unrelated information."},
                                    {"type": "text", "text": "Dont say anything like you cant know calories for sure just provide the best guess."},
                                    {
                                        "type": "image_url",
                                        "image_url": {
                                            "url": f"data:{mime_type_for_openai};base64,{image_base64}"
                                        }
                                    },
                                ],
                            }
                        ],
                        temperature=0,
                    )
                    ai_result = response.choices[0].message.content 
                    # Extract calorie value (first integer found in the response)
                    match = re.search(r'(\d+)\s*(?:kcal|calories|calorie)?', ai_result, re.IGNORECASE)
                    calories = int(match.group(1)) if match else None

                    # Extract food name from the phrase "The food item you uploaded is name"
                    name_match = re.search(r"The food item you uploaded is ([\w\s\-']+)", ai_result, re.IGNORECASE)
                    food_name = name_match.group(1).strip() if name_match else "Unknown"

                    print(f"Food: {food_name}, Calories: {calories}")
                    # Pass the path of the (potentially converted) file to the template
                    return render_template('custom_calories.html', img_path=new_filename, ai_result=ai_result, calories=calories, food_name=food_name)
                else:
                    flash('Could not process image.', 'error')
                    return redirect(url_for('custom_calories'))

            except Exception as e:
                app.logger.error(f"Error processing uploaded file: {e}")
                flash(f'Error processing file: {str(e)}', 'error')
                return redirect(url_for('custom_calories'))
        else: # This 'else' corresponds to 'if file and allowed_file(file.filename)'
            flash('Invalid file type. Allowed types are: png, jpg, jpeg, heic.', 'error') # More specific message
            return redirect(url_for('custom_calories'))

    # GET request
    cleanup_uploads(app.config['UPLOAD_FOLDER'], max_age_seconds=86400)
    return render_template('custom_calories.html')

@app.route('/add_food/<int:entry_id>', methods=['POST'])
@login_required
def add_food(entry_id):
    entry = SavedCalories.query.filter_by(id=entry_id, user_id=current_user.id).first()
    if not entry:
        flash('No entry found for this user.', 'error')
        return redirect(url_for('saved'))
    name = request.form.get('food_name')
    calories = request.form.get('food_calories')
    if name and calories:
        food = FoodItem(saved_calories_id=entry.id, name=name, calories=int(calories))
        db.session.add(food)
        db.session.commit()
        flash('Food item added!', 'success')
    else:
        flash('Please provide both food name and calories.', 'error')
    return redirect(url_for('saved'))

def get_saved_data():
    saved_data = SavedCalories.query.filter_by(user_id=current_user.id).all()
    if not saved_data:
        return []
    result = []
    for data in saved_data:
        foods = FoodItem.query.filter_by(saved_calories_id=data.id).all()
        total_calories = sum(f.calories for f in foods)
        result.append({
            'id': data.id,
            'date': data.date,
            'foods': [{'name': f.name, 'calories': f.calories} for f in foods],
            'total_calories': total_calories,
            'total_calories_today': total_calories if data.date == dt.now(pytz.timezone(current_user.timezone or 'UTC')).strftime("%Y-%m-%d") else 0,
        })
    result.sort(key=lambda x: dt.strptime(x['date'], "%Y-%m-%d"), reverse=True)
    return result


@app.route('/profile')
@login_required
def profile():
    username = current_user.username
    email = current_user.email
    return render_template('profile.html', username=username, email=email)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    ai_suggestion = None
    if request.method == 'POST':
        if request.form.get('ai_suggest'):
            ai_suggestion = ai_reccomend_daily_calories()
        else:
            # Update daily calorie goal
            daily_calorie_goal_str = request.form.get('daily_calorie_goal')
            if daily_calorie_goal_str:
                try:
                    current_user.daily_calorie_goal = int(daily_calorie_goal_str)
                    flash('Daily calorie goal updated!', 'success')
                except ValueError:
                    flash('Please provide a valid number for calorie goal.', 'error')
            
            # Update profile information
            age_str = request.form.get('age')
            weight_str = request.form.get('weight')
            height_str = request.form.get('height')
            gender = request.form.get('gender')

            profile_updated = False
            try:
                if age_str: current_user.age = int(age_str)
                if weight_str: current_user.weight = float(weight_str)
                if height_str: current_user.height = float(height_str)
                if gender: current_user.gender = str(gender)
                profile_updated = True # Mark if any field was processed
            except ValueError:
                flash('Invalid format for age, weight, or height.', 'error')
                profile_updated = False # Reset if error

            if profile_updated:
                flash('Profile information updated!', 'success')

            # Update notification preferences
            current_user.notifications_enabled = 'notifications_enabled' in request.form
            current_user.notify_meal_reminder = 'notify_meal_reminder' in request.form
            current_user.notify_goal_achievement = 'notify_goal_achievement' in request.form # This is the relevant one
            reminder_time_str = request.form.get('reminder_time')
            if reminder_time_str:
                current_user.reminder_time = reminder_time_str
            
            flash('Notification preferences updated!', 'success')
            
            db.session.commit() # Commit all changes together
            return redirect(url_for('settings')) # Redirect to avoid re-POST on refresh
    
    # Prepare template variables
    template_vars = {
        'daily_calorie_goal': current_user.daily_calorie_goal,
        'age': current_user.age,
        'weight': current_user.weight,
        'height': current_user.height,
        'gender': current_user.gender,
        'ai_suggestion': ai_suggestion
    }
    
    # Add notification preferences if they exist in the user model
    if hasattr(current_user, 'notifications_enabled'):
        template_vars.update({
            'notifications_enabled': getattr(current_user, 'notifications_enabled', False),
            'notify_meal_reminder': getattr(current_user, 'notify_meal_reminder', False),
            'notify_goal_achievement': getattr(current_user, 'notify_goal_achievement', True),
            'reminder_time': getattr(current_user, 'reminder_time', None)
        })
    
    return render_template('settings.html', **template_vars)

def push_data(calories, date=dt.now().strftime("%Y-%m-%d"), food_name="Custom"):
    entry = SavedCalories.query.filter_by(date=date, user_id=current_user.id).first()
    if not entry:
        entry = SavedCalories(date=date, user_id=current_user.id)
        db.session.add(entry)
        db.session.flush() # Ensure entry.id is available if new
    
    try:
        calories_int = int(calories)
        food = FoodItem(saved_calories_id=entry.id, name=food_name, calories=calories_int)
        db.session.add(food)
        db.session.commit()
        check_and_send_goal_achievement_notification(current_user, calories_int)
    except ValueError:
        app.logger.error(f"Invalid calorie value '{calories}' in push_data for user {current_user.id}")
        # Optionally flash a message if this function could lead to user feedback
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in push_data for user {current_user.id}: {e}")


@app.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_data(entry_id):
    data = SavedCalories.query.filter_by(id=entry_id, user_id=current_user.id).first()
    if data:
        db.session.delete(data)
        db.session.commit()
        flash('Data deleted successfully!', 'success')
    else:
        flash('No data found for the given entry.', 'error')
    return redirect(url_for('saved'))

@app.route('/edit/<int:entry_id>', methods=['POST'])
@login_required
def edit_data(entry_id):
    data = SavedCalories.query.filter_by(id=entry_id, user_id=current_user.id).first()
    new_calories = request.form.get('calories')
    if data and new_calories:
        # Optionally update all food items' calories, or handle as needed
        for food in data.food_items:
            food.calories = int(new_calories)
        db.session.commit()
        flash('Data updated successfully!', 'success')
    else:
        flash('No data found for the given entry.', 'error')
    return redirect(url_for('saved'))

@app.route('/diet', methods=['GET', 'POST'])
@login_required
def diet():
    today = dt.now().strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(date=today, user_id=current_user.id).first()
    calories_consumed = sum(f.calories for f in entry.food_items if f.calories is not None) if entry else 0
    
    # Ensure daily_calorie_goal is set, redirect to settings if not
    if current_user.daily_calorie_goal is None:
        flash('Please set your daily calorie goal in settings.', 'warning')
        return redirect(url_for('settings'))
        
    daily_calorie_goal = current_user.daily_calorie_goal # Already checked it's not None

    motivational_tip = get_motivational_tip()

    return render_template(
        'diet.html',
        calories_consumed=calories_consumed,
        daily_calorie_goal=daily_calorie_goal,
        motivational_tip=motivational_tip
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_email(subject, recipient, body):
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    mail.send(msg)

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(config.SECRET_KEY)
    return serializer.dumps(email, salt=config.SECURITY_PASSWORD_SALT)

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(config.SECRET_KEY)
    try:
        email = serializer.loads(token, salt=config.SECURITY_PASSWORD_SALT, max_age=expiration)
    except Exception:
        return None
    return email


@shared_task(bind=True)
def generate_ai_analysis_task(self, user_id):
    """
    Celery task to generate AI nutrition analysis asynchronously.
    """
    with app.app_context():
        user = User.query.get(user_id)
        if not user:
            self.update_state(state='FAILURE', meta={'error': 'User not found'})
            return {'status': 'FAILURE', 'error': 'User not found'}

        # Assume profile is complete based on check in api_ai_analysis
        weight = user.weight
        height = user.height
        age = user.age
        gender = user.gender
        calorie_goal = user.daily_calorie_goal
        
        user_timezone = user.timezone or 'UTC'
        today_str = dt.now(pytz.timezone(user_timezone)).strftime("%Y-%m-%d")
        now_time = dt.now(pytz.timezone(user_timezone)).strftime("%H:%M")

        entry = SavedCalories.query.filter_by(date=today_str, user_id=user.id).first()
        food_entries = {food.name: food.calories for food in entry.food_items} if entry and entry.food_items else {}
        total_calories_today = sum(food_entries.values())

        prompt = (
            f"You are a helpful nutrition assistant. "
            f"Here is today's user data:\n"
            f"- Date: {today_str}\n"
            f"- Time: {now_time}\n"
            f"- Age: {age}\n"
            f"- Weight: {weight} kg\n"
            f"- Height: {height} cm\n"
            f"- Gender: {gender}\n"
            f"- Daily Calorie Goal: {calorie_goal} kcal\n"
            f"- Total Calories Consumed Today: {total_calories_today} kcal\n"
            f"- Foods consumed today (name: calories): {food_entries}\n\n"
            "Please provide a brief markdown-formatted analysis of the user's day so far, "
            "including:\n"
            "- A summary of their calorie intake\n"
            "- At least one tip for improvement or encouragement\n"
            "- Suggestions for the rest of the day if needed\n"
            "Be concise, friendly, and use bullet points or sections where appropriate.\n"
            "Do not include any unrelated information or disclaimers.\n"
            "your response should be in markdown format and it should be stylish and playfull but nothing too much.\n"
            "Do not show the age weight height and gender in the response.\n"
        )

        try:
            response = call_openai_api_with_fallback(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful nutrition and calorie tracking assistant."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=400,
                user=get_hashed_user_id(user.id)
            )
            analysis = response.choices[0].message.content
            return {'status': 'SUCCESS', 'analysis': analysis}
        except Exception as e:
            app.logger.error(f"Error in generate_ai_analysis_task for user {user_id}: {e}")
            meta = {'exc_type': type(e).__name__, 'exc_message': str(e)}
            self.update_state(state='FAILURE', meta=meta)
            return {'status': 'FAILURE', 'error': 'An error occurred during analysis.'}

@app.route('/api/ai-analysis')
@login_required
def api_ai_analysis():
    # Check if profile is complete before starting anything
    if not all([current_user.weight, current_user.height, current_user.age, current_user.gender, current_user.daily_calorie_goal]):
        flash('Please set your profile information in settings to use AI Analysis.', 'warning')
        return jsonify({'status': 'PROFILE_INCOMPLETE', 'redirect_url': url_for('settings')})

    task_id = session.get('ai_analysis_task_id')
    
    if task_id:
        task = generate_ai_analysis_task.AsyncResult(task_id)
        if task.state == 'PENDING' or task.state == 'STARTED':
            return jsonify({'status': 'PENDING'})
        elif task.state == 'SUCCESS':
            session.pop('ai_analysis_task_id', None)
            result = task.get()
            analysis = result.get('analysis')
            
            # Cache the successful result in session
            today = dt.now(pytz.timezone(current_user.timezone or 'UTC')).strftime("%Y-%m-%d")
            cache_key = f"ai_analysis_{today}_{current_user.id}"
            session[cache_key] = analysis
            
            return jsonify({'status': 'SUCCESS', 'analysis': analysis})
        elif task.state == 'FAILURE':
            session.pop('ai_analysis_task_id', None)
            return jsonify({'status': 'FAILURE', 'message': 'Analysis failed to generate.'}), 500

    # No running task, check cache before starting a new one
    today = dt.now(pytz.timezone(current_user.timezone or 'UTC')).strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(date=today, user_id=current_user.id).first()
    total_calories_today = sum(f.calories for f in entry.food_items) if entry else 0

    cache_key = f"ai_analysis_{today}_{current_user.id}"
    cache_cal_key = f"ai_analysis_cal_{today}_{current_user.id}"
    cached_analysis = session.get(cache_key)
    cached_calories = session.get(cache_cal_key)

    if cached_analysis is not None and cached_calories == total_calories_today:
        return jsonify({'status': 'SUCCESS', 'analysis': cached_analysis})

    # Start a new task
    task = generate_ai_analysis_task.delay(current_user.id)
    session['ai_analysis_task_id'] = task.id
    session[cache_cal_key] = total_calories_today

    return jsonify({'status': 'PENDING'})


@app.route('/api/get_diet_plan_item_statuses', methods=['GET'])
@login_required
def api_get_diet_plan_item_statuses():
    """
    Returns a list of food names that the current user has logged (marked as "done")
    for today in their SavedCalories.
    """
    today_date_str = dt.now().strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(user_id=current_user.id, date=today_date_str).first()
    
    done_foods = []
    if entry:
        food_items_for_today = FoodItem.query.filter_by(saved_calories_id=entry.id).all()
        done_foods = [item.name for item in food_items_for_today]
        
    return jsonify({'done_foods': done_foods})

@app.route('/api/update_diet_plan_item', methods=['POST'])
@login_required
def api_update_diet_plan_item():
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid request. No data provided.'}), 400

    meal_item_id = data.get('meal_item_id')
    new_food_name = data.get('food_name')
    new_quantity = data.get('quantity') # This will be a string, can be empty
    new_calories = data.get('calories') # This can be an integer or null

    if not meal_item_id:
        return jsonify({'status': 'error', 'message': 'Meal item ID is required.'}), 400
    
    if new_food_name is None or new_food_name.strip() == "": # Food name must not be empty
        return jsonify({'status': 'error', 'message': 'Food name cannot be empty.'}), 400

    # Validate calories if provided (it can be null)
    if new_calories is not None:
        try:
            new_calories = int(new_calories)
            if new_calories < 0:
                raise ValueError("Calories cannot be negative.")
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'Invalid calorie format. Must be a non-negative integer or null.'}), 400

    # Find the meal item and ensure it belongs to the current user
    meal_item = db.session.query(MealItem).join(Meal).join(UserDietDay).filter(
        MealItem.id == meal_item_id,
        UserDietDay.user_id == current_user.id
    ).first()

    if not meal_item:
        return jsonify({'status': 'error', 'message': 'Meal item not found or access denied.'}), 404

    try:
        meal_item.food_name = new_food_name.strip()
        meal_item.quantity = new_quantity.strip() if new_quantity is not None else None # Store empty string as None or as is, depending on preference
        meal_item.calories = new_calories # Assign directly, can be int or None

        db.session.commit()

        updated_item_data = {
            "id": meal_item.id,
            "food_name": meal_item.food_name,
            "calories": meal_item.calories,
            "quantity": meal_item.quantity,
            "notes": meal_item.notes # Include notes even if not edited by this form
        }
        return jsonify({'status': 'success', 'message': 'Diet plan item updated successfully.', 'updated_item': updated_item_data}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating meal item {meal_item_id}: {e}")
        return jsonify({'status': 'error', 'message': f'An internal error occurred: {str(e)}'}), 500

@app.route('/api/get_diet_generation_status/<generation_token>')
@login_required
def get_diet_generation_status_api(generation_token):
    user = current_user
    if user.active_diet_generation_token == generation_token:
        status = user.last_diet_generation_status
        return jsonify({'status': status, 'token_match': True})
    else:
        # If the active token is different, this token is outdated or invalid.
        # We could also check if last_diet_generation_status is 'completed' for this specific token
        # if we didn't clear active_diet_generation_token upon completion/failure.
        # For now, a simple mismatch implies the task is no longer the primary one being tracked.
        return jsonify({'status': 'unknown', 'token_match': False, 'message': 'Token mismatch or task superseded.'})

def ai_reccomend_daily_calories():
    age = current_user.age
    weight = current_user.weight
    height = current_user.height
    if not all([age, weight, height]):
        flash('Please provide your age, weight, and height in settings.', 'warning')
        return redirect(url_for('settings'))

    response = call_openai_api_with_fallback(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a calorie calculator assistant. Use the Mifflin-St Jeor equation "
                    "and a sedentary activity level (1.2 multiplier) to calculate daily caloric needs. "
                    "Only output values for maintenance, deficit (20%), and surplus (20%) in kcal. "
                    "Label each with percentage differences. Do not add any explanations or extra text."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Age: {age}\n"
                    f"Weight: {weight} kg\n"
                    f"Height: {height} cm\n\n"
                    "Please provide daily caloric needs for:\n"
                    "- Maintenance\n"
                    "- 20% Deficit (cutting)\n"
                    "- 20% Surplus (bulking)\n\n"
                    "Show the kcal values and percentage differences only. No explanation or other output. "
                    "Round all calorie values to the nearest decade (e.g., 1874 → 1870)."
                ),
            },
        ],
        temperature=0,
        user=get_hashed_user_id()
    )

    return response.choices[0].message.content


def get_motivational_tip():
    quotes = [
        "Eat to fuel your body, not to feed your emotions.",
        "Small changes every day add up to big results.",
        "Your body deserves the best. Treat it with respect.",
        "Healthy eating is a form of self-respect.",
        "Don’t count the days, make the days count—with good choices.",
        "You don’t have to eat less, you just have to eat right.",
        "The food you eat can be either the safest and most powerful form of medicine or the slowest form of poison.",
        "Take care of your body. It’s the only place you have to live.",
        "Every healthy choice is a victory.",
        "Discipline is choosing between what you want now and what you want most.",
        "A healthy outside starts from the inside.",
        "Progress, not perfection.",
        "You are what you eat, so don’t be fast, cheap, easy, or fake.",
        "Your diet is a bank account. Good food choices are good investments.",
        "Strive for progress, not perfection.",
        "Eat better, feel better, live better.",
        "The secret of getting ahead is getting started.",
        "Don’t dig your grave with your own knife and fork.",
        "It’s not a diet, it’s a lifestyle.",
        "Success is the sum of small efforts, repeated day in and day out."
    ]
    return random.choice(quotes)

def create_admin_user():
    if not User.query.filter_by(username=config.ADMIN_USERNAME).first():
        hashed_password = bcrypt.generate_password_hash(config.ADMIN_PASSWORD).decode('utf-8')
        admin_user = User(
            username=config.ADMIN_USERNAME,
            password=hashed_password,
            email=config.ADMIN_EMAIL,
            is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

@app.route('/landing')
def landing():
    return render_template('landing.html')

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    """
    Handle Google OAuth login: fetch user info, create or login the user, then redirect.
    """
    if not token:
        flash("Failed to log in with Google.", "error")
        return False
    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "error")
        return False
    info = resp.json()
    email = info.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        password = bcrypt.generate_password_hash(secrets.token_urlsafe(32)).decode('utf-8')
        user = User(username=email, email=email, password=password)
        db.session.add(user)
        db.session.commit()
    login_user(user, remember=True)
    flash("Logged in with Google!", "success")
    return False  # prevent Flask-Dance from storing OAuth token in session

@app.route('/describe_meal', methods=['POST'])
@login_required
def describe_meal():
    description = request.form.get('meal_description')
    if not description:
        flash('Please describe your meal.', 'error')
        return redirect(url_for('saved'))

    prompt = (
        "Extract all food items and estimate calories for each from this meal description. "
        "Respond ONLY with a JSON array of objects with 'name' and 'calories' fields. "
        "No explanation, no extra text. Example: "
        '[{"name": "chicken breast", "calories": 200}, {"name": "rice", "calories": 180}]\n\n'
        f"Meal description: {description}"
    )
    foods = []
    total_calories_from_meal = 0
    try:
        response = call_openai_api_with_fallback(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful nutrition assistant that extracts food items and calories into a strict JSON format."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.2,
            user=get_hashed_user_id()
        )
        ai_content = response.choices[0].message.content.strip()
        
        # Try to find JSON array within the response
        match = re.search(r'\[\s*\{.*\}\s*\]', ai_content, re.DOTALL)
        if match:
            json_str = match.group(0)
            foods = json.loads(json_str)
            if not isinstance(foods, list): # Ensure it's a list
                foods = []
                app.logger.warning(f"AI response for describe_meal (user {current_user.id}) was valid JSON but not a list: {json_str}")
        else:
            app.logger.warning(f"Could not extract valid JSON array from AI response for describe_meal (user {current_user.id}). Response: {ai_content}")
            flash('Could not extract foods from AI response. Please try rephrasing or check AI output format.', 'warning')
            
    except json.JSONDecodeError as e:
        app.logger.error(f"JSONDecodeError in describe_meal for user {current_user.id}: {e}. AI content: {ai_content}")
        flash('Error parsing food data from AI. Please try again.', 'error')
    except Exception as e:
        app.logger.error(f"OpenAI/JSON error in describe_meal for user {current_user.id}: {e}")
        flash('Could not analyze meal due to an unexpected error. Please try again.', 'error')

    if foods:
        today = dt.now().strftime("%Y-%m-%d")
        entry = SavedCalories.query.filter_by(date=today, user_id=current_user.id).first()
        if not entry:
            entry = SavedCalories(date=today, user_id=current_user.id)
            db.session.add(entry)
            db.session.flush() # Ensure entry.id is available

        items_added_count = 0
        for food_data in foods:
            name = food_data.get('name')
            calories_val = food_data.get('calories')
            if name and calories_val is not None:
                try:
                    calories = int(calories_val)
                    if calories >= 0: # Allow 0 calorie items if intended
                        db.session.add(FoodItem(saved_calories_id=entry.id, name=str(name), calories=calories))
                        total_calories_from_meal += calories
                        items_added_count += 1
                except ValueError:
                    app.logger.warning(f"Invalid calorie value '{calories_val}' for item '{name}' in describe_meal for user {current_user.id}.")
        
        if items_added_count > 0:
            db.session.commit()
            flash(f'{items_added_count} food item(s) analyzed and added!', 'success')
            if total_calories_from_meal > 0: # Only check if actual calories were added
                 check_and_send_goal_achievement_notification(current_user, total_calories_from_meal)
        elif not foods: # If initial foods list was empty or became empty
             flash('No valid food items were extracted from the description.', 'info')


    return redirect(url_for('saved'))

@app.route('/api/add_diet_food', methods=['POST'])
@login_required
def api_add_diet_food(): # Renamed from api_diet_plan
    data = request.json
    if not data or 'food_name' not in data or 'calories' not in data:
        return jsonify({'error': 'Invalid input, food_name and calories required'}), 400
    
    food_name = data['food_name']
    try:
        calories = int(data['calories']) # Ensure calories is an int
    except ValueError:
        return jsonify({'error': 'Invalid calorie format'}), 400

    if not isinstance(food_name, str): # Basic type check
        return jsonify({'error': 'Invalid data format for food_name'}), 400

    today_date_str = dt.now().strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(date=today_date_str, user_id=current_user.id).first()
    if not entry:
        entry = SavedCalories(date=today_date_str, user_id=current_user.id)
        db.session.add(entry)
        db.session.flush() # Make entry.id available
    
    # Check if this food item already exists for this entry to prevent duplicates if re-clicked
    existing_food_item = FoodItem.query.filter_by(saved_calories_id=entry.id, name=food_name).first()
    if not existing_food_item:
        food = FoodItem(saved_calories_id=entry.id, name=food_name, calories=calories)
        db.session.add(food)
        db.session.commit()
        check_and_send_goal_achievement_notification(current_user, calories)
        return jsonify({'status': 'success', 'message': 'Food item added'}), 200
    else:
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Food item already logged for today'}), 200

@app.route('/api/remove_diet_food', methods=['POST'])
@login_required
def api_remove_diet_food():
    data = request.json
    if not data or 'food_name' not in data:
        return jsonify({'error': 'Invalid input, food_name required'}), 400
    
    food_name = data['food_name']

    today_date_str = dt.now().strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(date=today_date_str, user_id=current_user.id).first()
    
    if not entry:
        # If there's no entry for today, the food couldn't have been logged.
        return jsonify({'status': 'success', 'message': 'No saved calories entry for today, nothing to remove.'}), 200

    food_item = FoodItem.query.filter_by(saved_calories_id=entry.id, name=food_name).first()
    
    if food_item:
        db.session.delete(food_item)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Food item removed'}), 200
    else:
        # Food item not found in today's log.
        return jsonify({'status': 'success', 'message': 'Food item not found in today\'s log.'}), 200
    
@app.route('/create_diet_plan', methods=['GET', 'POST'])
@login_required
def create_diet_plan():
    current_weekday = dt.now().strftime("%A")
    user = current_user
    today = dt.today() # Use dt.today() for date objects
    max_generations_per_day = 2

    if user.last_plan_generation_date != today:
        user.plan_generations_today = 0
        user.last_plan_generation_date = today
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error resetting generation count for user {user.id}: {e}")
    
    generations_left_today = max(0, max_generations_per_day - user.plan_generations_today)
        
    if request.method == 'POST':
        describe_diet = request.form.get('describe_diet')
        if not describe_diet:
            flash('Please describe your diet plan if you want to generate a new one.', 'error')
            return redirect(url_for('create_diet_plan'))

        if not all([user.daily_calorie_goal, user.weight, user.height, user.age, user.gender]):
            flash('Please complete your profile in settings before generating a diet plan.', 'error')
            return redirect(url_for('settings')) 

        if user.plan_generations_today >= max_generations_per_day and not user.is_admin:
            flash(f'You have reached the maximum of {max_generations_per_day} diet plan generations for today.', 'warning')
            return redirect(url_for('create_diet_plan'))

        if not user.is_admin: # Only increment for non-admins if you want admins to have unlimited without count
            user.plan_generations_today += 1
        
        generation_token = secrets.token_hex(16)
        user.active_diet_generation_token = generation_token
        user.last_diet_generation_status = "pending"
        
        try:
            db.session.commit() 
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error setting up diet generation token or count for user {user.id}: {e}")
            flash('An error occurred preparing the diet generation. Please try again.', 'error')
            return redirect(url_for('create_diet_plan'))

        thread = threading.Thread(target=run_plan_generation_in_background, args=(app, user.id, describe_diet, generation_token))
        thread.daemon = True 
        thread.start()
        
        # Redirect to a new status page, passing the token
        return redirect(url_for('diet_plan_generating_status_page', generation_token=generation_token))

    plan = get_existing_diet_plan()
    return render_template(
        'create_diet_plan.html', 
        current_day_name=current_weekday, 
        diet_plan=plan,
        generations_left_today=generations_left_today,
        max_generations_per_day=max_generations_per_day
    )

# This is the wrapper function that the thread will execute
def run_plan_generation_in_background(flask_app, user_id, describe_diet, generation_token):
    with flask_app.app_context():
        generate_and_store_diet_plan_logic(user_id, describe_diet, generation_token)

def generate_and_store_diet_plan_logic(user_id, describe_diet='', generation_token=None):
    user = User.query.get(user_id)
    final_status_to_set = "failed"
    items_added_to_db = 0

    if not user:
        app.logger.error(f"Thread: User with ID {user_id} not found for plan generation (Token: {generation_token}).")
        return False 

    if user.active_diet_generation_token != generation_token:
        app.logger.info(f"Thread: Diet generation task for user {user_id} with token {generation_token} was superseded or is invalid. Exiting.")
        return False

    try:
        app.logger.info(f"Thread: Starting diet plan generation for user {user_id}, token {generation_token}.")
        calorie_goal = user.daily_calorie_goal
        weight = user.weight
        height = user.height
        age = user.age
        gender = user.gender

        prompt = (
            f"Generate a weekly diet plan for a user with the following details:\n"
            f"- Daily Calorie Goal: Approximately {calorie_goal or 'not set'} kcal\n"
            f"- Weight: {weight or 'not set'} kg\n"
            f"- Height: {height or 'not set'} cm\n"
            f"- Age: {age or 'not set'} years\n"
            f"- Gender: {gender or 'not set'}\n"
            f"- User's preferences: {describe_diet}\n\n"
            f"The plan should cover all 7 days of the week (Monday to Sunday).\n"
            f"For each day, include the following meal types: Breakfast, Mid-Morning Snack, Lunch, Afternoon Snack, Dinner, Evening Snack.\n"
            f"For each meal, provide a list of food items. Each food item object must include:\n"
            f"  - 'food_name' (string): The name of the food.\n"
            f"  - 'calories' (integer): Estimated calorie count. This field is mandatory.\n"
            f"  - 'quantity' (string): The amount (e.g., '1 cup', '100g', '1 medium apple').\n"
            f"  - 'notes' (string, optional): Brief notes, if any (e.g., 'with skim milk'). If no notes, this can be an empty string or omitted.\n\n"
            f"The total calories for each day should be as close as possible to the user's daily calorie goal.\n"
            f"Return the entire plan STRICTLY as a single JSON object. Do NOT include any explanatory text, markdown, or anything else outside of the JSON object.\n"
            f"The JSON object should have days of the week as top-level keys (e.g., 'Monday', 'Tuesday', ...).\n"
            f"Each day key should map to an object containing meal types as keys the only allowed keys are ('Breakfast', 'Mid-Morning Snack', 'Lunch', 'Afternoon Snack', 'Dinner', 'Evening Snack')\n"
            f"You dont need to provide all the meal types just as many as necessary for the ideal diet programm \n"
            f"Each meal type key should map to an array of food item objects as described above.\n\n"
            f"Example of the required JSON structure for one day and one meal:\n"
            f"{{\n"
            f"  \"Monday\": {{\n"
            f"    \"Breakfast\": [\n"
            f"      {{\n"
            f"        \"food_name\": \"Oatmeal\",\n"
            f"        \"calories\": 300,\n"
            f"        \"quantity\": \"1 cup\",\n"
            f"        \"notes\": \"Made with water and a sprinkle of cinnamon\"\n"
            f"      }},\n"
            f"      {{\n"
            f"        \"food_name\": \"Banana\",\n"
            f"        \"calories\": 105,\n"
            f"        \"quantity\": \"1 medium\"\n"
            f"      }}\n"
            f"    ],\n"
            f"    \"Mid-Morning Snack\": [\n"
            f"      // ... more items ...\n"
            f"    ]\n"
            f"    // ... other meal types ...\n"
            f"  }},\n"
            f"  \"Tuesday\": {{\n"
            f"    // ... meals and items for Tuesday ...\n"
            f"  }}\n"
            f"  // ... etc. for all 7 days ...\n"
            f"}}\n"
            f"Ensure the output is ONLY the JSON object."
        )
        
        ai_generated_plan_str = None
        try:
            response = call_openai_api_with_fallback(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a diet planning assistant that outputs JSON."},
                    {"role": "user", "content": prompt}
                ],
                user=get_hashed_user_id(user_id),
                response_format={"type": "json_object"}
            )
            ai_generated_plan_str = response.choices[0].message.content
            parsed_plan = json.loads(ai_generated_plan_str)
        except json.JSONDecodeError as e:
            app.logger.error(f"Thread: AI JSONDecodeError for user {user_id} (Token: {generation_token}). Error: {e}. Response: {ai_generated_plan_str[:500] if ai_generated_plan_str else 'None'}")
            raise
        except Exception as e:
            app.logger.error(f"Thread: OpenAI API call error for user {user_id} (Token: {generation_token}): {e}")
            raise

        if not parsed_plan or not isinstance(parsed_plan, dict) or not any(parsed_plan.values()):
            app.logger.warning(f"Thread: AI returned empty/invalid plan for user {user_id} (Token: {generation_token}). Plan: {parsed_plan}")
        else:
            UserDietDay.query.filter_by(user_id=user_id).delete(synchronize_session='fetch')
            app.logger.info(f"Thread: Marked old diet days for user {user_id} for deletion.")
            try:
                db.session.flush() # Execute pending DELETE SQL statements in the transaction
                app.logger.info(f"Thread: Flushed session after marking deletions for user {user_id}.")
            except Exception as e_flush:
                # Log the flush error, but proceed. The final commit will likely fail if this is critical.
                app.logger.error(f"Thread: Error flushing session after deletions for user {user_id}: {e_flush}")
                # Depending on the error, you might choose to raise it or handle it differently.
                # For now, we log and let the subsequent operations attempt.

            DAY_NAME_TO_ENUM = {day.value: day for day in DayOfWeekEnum}
            MEAL_TYPE_TO_ENUM = {meal.value: meal for meal in MealTypeEnum}

            for day_name_str, meals_data in parsed_plan.items():
                day_enum = DAY_NAME_TO_ENUM.get(day_name_str)
                if not day_enum:
                    app.logger.warning(f"Thread: Unknown day '{day_name_str}' for user {user_id}. Skipping.")
                    continue
                
                app.logger.info(f"Thread: Processing day '{day_enum.value}' for user {user_id}.")
                diet_day = UserDietDay(user_id=user_id, day_of_week=day_enum)
                db.session.add(diet_day)
                items_added_to_db +=1
                app.logger.info(f"Thread: Added UserDietDay for '{day_enum.value}' to session. Object: {diet_day}")

                _meals_created_for_this_day = {}
                app.logger.debug(f"Thread: Initialized _meals_created_for_this_day for '{day_enum.value}': {list(_meals_created_for_this_day.keys())}")

                if not isinstance(meals_data, dict):
                    app.logger.warning(f"Thread: Expected dict for meals_data in '{day_name_str}', user {user_id}. Got {type(meals_data)}. Skipping day.")
                    continue

                # 1. Merge all items for each meal type (normalize keys)
                merged_meals = {}
                for meal_type_str, items_data in meals_data.items():
                    # Normalize meal type string
                    normalized_meal_type_str = meal_type_str.strip().title()
                    meal_type_enum = MEAL_TYPE_TO_ENUM.get(normalized_meal_type_str)
                    if not meal_type_enum:
                        app.logger.warning(f"Thread: Day '{day_enum.value}': Unknown meal type string '{meal_type_str}'. Skipping this meal type.")
                        continue
                    if not isinstance(items_data, list):
                        app.logger.warning(f"Thread: Day '{day_enum.value}', Meal '{meal_type_enum}': Expected list for items_data. Got {type(items_data)}. Skipping items for this meal.")
                        continue
                    merged_meals.setdefault(meal_type_enum, []).extend(items_data)

                # 2. Defensive: Remove any existing Meal objects for this day/meal_type in the session (shouldn't be needed, but just in case)
                for meal_type_enum in merged_meals.keys():
                    existing_meal = Meal.query.filter_by(user_diet_day=diet_day, meal_type=meal_type_enum).first()
                    if existing_meal:
                        db.session.delete(existing_meal)
                        db.session.flush()

                # 3. Now create only one Meal per meal_type_enum
                for meal_type_enum, items_data in merged_meals.items():
                    meal_obj = Meal(user_diet_day=diet_day, meal_type=meal_type_enum)
                    db.session.add(meal_obj)
                    items_added_to_db += 1
                    for item_dict in items_data:
                        if not isinstance(item_dict, dict):
                            continue
                        food_name = item_dict.get('food_name')
                        calories_val = item_dict.get('calories')
                        quantity = item_dict.get('quantity')
                        notes = item_dict.get('notes', '')
                        if not food_name or not isinstance(food_name, str) or food_name.strip() == "":
                            continue
                        if calories_val is None:
                            continue
                        try:
                            calories = int(calories_val)
                        except (ValueError, TypeError):
                            continue
                        meal_item = MealItem(
                            meal=meal_obj,
                            food_name=food_name.strip(),
                            calories=calories,
                            quantity=quantity.strip() if quantity and isinstance(quantity, str) else quantity,
                            notes=notes.strip() if notes and isinstance(notes, str) else notes
                        )
                        db.session.add(meal_item)
                        items_added_to_db += 1
            
            if items_added_to_db > 0:
                app.logger.info(f"Thread: Attempting to commit {items_added_to_db} DB objects for user {user_id}, token {generation_token}.")
                db.session.commit()
                app.logger.info(f"Thread: Successfully committed diet plan for user {user_id}, token {generation_token}.")
                final_status_to_set = "completed"
            else:
                app.logger.warning(f"Thread: No valid diet items processed for user {user_id}, token {generation_token}. Plan considered failed.")
                db.session.rollback() # Rollback if only deletions happened but no new items.

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Thread: General exception during plan generation for user {user_id} (Token: {generation_token}): {e}")
        import traceback
        app.logger.error(traceback.format_exc()) # Ensure full traceback is logged
        final_status_to_set = "failed"
    finally:
        with app.app_context(): 
            user_to_update_status = User.query.get(user_id)
            if user_to_update_status:
                if user_to_update_status.active_diet_generation_token == generation_token:
                    user_to_update_status.last_diet_generation_status = final_status_to_set
                    try:
                        db.session.commit()
                        app.logger.info(f"Thread: Final status for user {user_id}, token {generation_token} set to '{final_status_to_set}'.")
                    except Exception as se:
                        db.session.rollback()
                        app.logger.error(f"Thread: CRITICAL error committing final status '{final_status_to_set}' for user {user_id}, token {generation_token}. DB Error: {se}")
                else:
                    app.logger.info(f"Thread: Final status update for token {generation_token} (user {user_id}) skipped. Active token is '{user_to_update_status.active_diet_generation_token}'. Status was '{final_status_to_set}'.")
            else:
                app.logger.error(f"Thread: User {user_id} not found for final status update (Token: {generation_token}). Status was '{final_status_to_set}'.")
    
    return final_status_to_set == "completed"

def get_existing_diet_plan(): # Renamed for clarity
    user = current_user
    plan_data = {}
    diet_days_for_user = UserDietDay.query.filter_by(user_id=user.id).order_by(UserDietDay.day_of_week).all()
    
    if not diet_days_for_user: # If no days, return empty plan
        return {}

    for diet_day in diet_days_for_user:
        day_name = diet_day.day_of_week.value
        plan_data[day_name] = {}
        meals_for_day = Meal.query.filter_by(user_diet_day_id=diet_day.id).order_by(Meal.meal_type).all()
        for meal in meals_for_day:
            meal_type_name = meal.meal_type.value
            items_for_meal = MealItem.query.filter_by(meal_id=meal.id).all()
            plan_data[day_name][meal_type_name] = [
                {
                    "id": item.id,
                    "food_name": item.food_name,
                    "calories": item.calories,
                    "quantity": item.quantity,
                    "notes": item.notes
                } for item in items_for_meal
            ]
    return plan_data

@app.route('/diet_plan_generating/<generation_token>')
@login_required
def diet_plan_generating_status_page(generation_token):
    user = current_user
    initial_status = "pending" 
    # Check if the token matches and what the status is, to potentially skip polling
    if user.active_diet_generation_token == generation_token:
        initial_status = user.last_diet_generation_status
    # If token doesn't match, it might be an old link, JS will handle it.
    
    return render_template('diet_plan_generating.html', 
                           generation_token=generation_token,
                           initial_status=initial_status)

@app.route('/sw.js', methods=['GET'])
def serve_sw():
    return send_from_directory(app.root_path, 'sw.js', mimetype='application/javascript')

@app.route('/offline')
def offline_page():
    return render_template('offline.html')

@app.route('/.well-known/assetlinks.json')
def serve_assetlinks():
    static_folder_path = os.path.join(app.static_folder) # This usually points to 'd:\CalorieTracker\calorie_tracker\static'
    well_known_path = os.path.join(static_folder_path, '.well-known')
    
    return send_from_directory(os.path.join(app.static_folder, '.well-known'),
                               'assetlinks.json',
                               mimetype='application/json')

@app.route('/widget-template')
def widget_template():
    """Template for the Android widget"""
    return render_template('widget_template.html')

@app.route('/api/widget-data')
@login_required
def widget_data():
    """API endpoint to provide widget data"""
    try:
        today = dt.now().strftime("%Y-%m-%d")
        entry = SavedCalories.query.filter_by(date=today, user_id=current_user.id).first()
        calories_consumed = sum(f.calories for f in entry.food_items) if entry else 0
        daily_calorie_goal = current_user.daily_calorie_goal or 2000
        
        # Calculate progress percentage
        progress_percentage = min(100, (calories_consumed / daily_calorie_goal) * 100) if daily_calorie_goal > 0 else 0
        
        return jsonify({
            "calories_consumed": calories_consumed,
            "daily_calorie_goal": daily_calorie_goal,
            "remaining": max(0, daily_calorie_goal - calories_consumed),
            "progress_percentage": round(progress_percentage, 1),
            "status": "on_track" if calories_consumed <= daily_calorie_goal else "over_goal",
            "last_updated": dt.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "error": "Unable to fetch calorie data",
            "calories_consumed": 0,
            "daily_calorie_goal": 2000,
            "remaining": 2000,
            "progress_percentage": 0,
            "status": "error",
            "last_updated": dt.now().isoformat()
        }), 500

def get_hashed_user_id(user_id=None):
    """Cache the hashed user ID in Flask's session context (g) for the current user."""
    if not hasattr(g, 'hashed_user_id'):
        g.hashed_user_id = hashlib.md5(str(current_user.id if user_id is None else user_id).encode('utf-8')).hexdigest()
    return g.hashed_user_id


def send_push_notification(user, title, body, url="/"):
    # Ensure VAPID keys are loaded from config, not hardcoded if they were
    vapid_private_key = config.VAPID_PRIVATE_KEY
    vapid_claim_email = config.VAPID_CLAIM_EMAIL

    if not vapid_private_key or not vapid_claim_email:
        app.logger.error("VAPID_PRIVATE_KEY or VAPID_CLAIM_EMAIL not configured.")
        return

    vapid_claims = {"sub": f"mailto:{vapid_claim_email}"}
    subscriptions = PushSubscription.query.filter_by(user_id=user.id).all()

    if not subscriptions:
        app.logger.info(f"No push subscriptions found for user {user.id} to send '{title}' notification.")
        return

    app.logger.info(f"Attempting to send push notification '{title}' to {len(subscriptions)} subscription(s) for user {user.id}.")

    for sub in subscriptions:
        try:
            webpush(
                subscription_info={
                    "endpoint": sub.endpoint,
                    "keys": {
                        "p256dh": sub.p256dh,
                        "auth": sub.auth,
                    },
                },
                data=json.dumps({
                    "title": title,
                    "body": body,
                    "url": url,
                }),
                vapid_private_key=vapid_private_key,
                vapid_claims=vapid_claims,
            )
            app.logger.info(f"Successfully sent push to endpoint {sub.endpoint[:30]}... for user {user.id}")
        except WebPushException as ex:
            app.logger.warning(f"WebPush failed for user {user.id}, endpoint {sub.endpoint[:30]}...: {ex}")
            # Consider handling specific exceptions, e.g., 410 Gone to remove stale subscriptions
            if ex.response and ex.response.status_code == 410:
                app.logger.info(f"Subscription {sub.endpoint[:30]}... for user {user.id} is gone. Deleting.")
                db.session.delete(sub)
                db.session.commit()
        except Exception as e:
            app.logger.error(f"Unexpected error sending push to {sub.endpoint[:30]}... for user {user.id}: {e}")

def check_and_send_goal_achievement_notification(user, calories_of_last_added_item_or_meal):
    """
    Checks if the user has achieved their daily calorie goal after adding an item/meal
    and sends a push notification if the goal was just crossed and notifications are enabled.
    """
    if not user.is_authenticated or not getattr(user, 'notify_goal_achievement', True):
        app.logger.debug(f"Goal achievement notification skipped for user {user.id}: not authenticated or opted out.")
        return

    daily_goal = user.daily_calorie_goal
    if not daily_goal or daily_goal <= 0:
        app.logger.debug(f"Goal achievement notification skipped for user {user.id}: no valid daily goal set.")
        return

    # Ensure calories_of_last_added_item_or_meal is a number.
    # It represents the calories of the item(s) *just* added.
    try:
        calories_added = int(calories_of_last_added_item_or_meal)
    except (ValueError, TypeError):
        app.logger.warning(f"Goal achievement check for user {user.id}: invalid calories_of_last_added_item_or_meal ({calories_of_last_added_item_or_meal}). Skipping.")
        return

    today_date_str = dt.now().strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(user_id=user.id, date=today_date_str).first()
    
    if not entry:
        app.logger.debug(f"Goal achievement notification skipped for user {user.id}: no food entry for today.")
        return

    total_calories_today = sum(f.calories for f in entry.food_items if f.calories is not None)
    
    app.logger.info(f"User {user.id}: Checking goal. Total today: {total_calories_today}, Last item(s) cals: {calories_added}, Goal: {daily_goal}")

    # Check if the goal was crossed with the addition of the last item/meal
    if total_calories_today >= daily_goal and \
       (total_calories_today - calories_added) < daily_goal:
        
        app.logger.info(f"User {user.id} achieved daily calorie goal. Sending notification.")
        # Ensure url_for has app context if this function were ever moved outside routes.py
        # Here, it's fine as it's in routes.py.
        notification_url = url_for('diet', _external=True) # _external=True can be useful for notifications
        send_push_notification(
            user,
            title="🎉 Goal Achieved!",
            body=f"You've reached your daily calorie goal of {daily_goal} kcal!",
            url=notification_url
        )
    elif total_calories_today >= daily_goal:
        app.logger.info(f"User {user.id} is at/over goal, but threshold was not crossed by this addition. Total: {total_calories_today}, Prev total approx: {total_calories_today - calories_added}, Goal: {daily_goal}")
    else:
        app.logger.info(f"User {user.id} has not yet reached goal. Total: {total_calories_today}, Goal: {daily_goal}")

@app.route('/admin/send_custom_notifications', methods=['POST'])
@login_required
def send_custom_notifications():
    user_ids = []
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    user_ids_raw = request.form.get('user_ids', '').strip()
    if not user_ids_raw:
        user_ids = [str(user.id) for user in User.query.all()]
    else:
        user_ids = [uid.strip() for uid in user_ids_raw.split(',') if uid.strip()]
    title = request.form.get('title', 'Custom Notification')
    body = request.form.get('body', 'This is a custom notification.')
    url = request.form.get('url', '/')
    for user_id in user_ids:
        user = User.query.get(int(user_id))
        if user:
            try:
                send_push_notification(user, title, body, url)
            except Exception as e:
                app.logger.error(f"Error sending custom notification to user {user_id}: {e}")
                return jsonify({'error': f'Failed to send notification to user {user_id}'}), 500
    return jsonify({'status': True}), 200

@app.route('/api/user/set_timezone', methods=['POST'])
@login_required
def set_timezone():
    """Set the user's timezone."""
    timezone = request.json.get('timezone')
    if not timezone or timezone not in pytz.all_timezones:
        message = jsonify({'error': 'Timezone is required'}), 400 
        timezone = 'UTC'  # Default to UTC if not provided or invalid   
    try:
        current_user.timezone = timezone
        db.session.commit()
        message = jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error setting timezone for user {current_user.id}: {e}")
        db.session.rollback()
        message = jsonify({'error': 'Failed to set timezone'}), 500
    return message

@app.route('/api/schedule_meal_reminders', methods=['POST'])
@login_required
def schedule_meal_reminders_api():
    """API endpoint to schedule meal reminders for all users who have enabled them."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        schedule_meal_reminders()
        return jsonify({'status': 'success', 'message': 'Meal reminders scheduled successfully.'}), 200
    except Exception as e:
        app.logger.error(f"Error scheduling meal reminders: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to schedule meal reminders.'}), 500

@shared_task(name='calorie_tracker.routes.schedule_meal_reminders')
def schedule_meal_reminders():
    """Schedule meal reminders for users who have enabled them."""
    users = User.query.filter_by(notify_meal_reminder=True).all()
    for user in users:
        if not user.reminder_time or not user.timezone:
            continue

        reminder_time_str = user.reminder_time  # already a string in 'HH:MM' format
        send_at.delay(user.id, reminder_time_str)

@celery.task(name='calorie_tracker.routes.send_at')
def send_at(user_id, reminder_time_str):  # Accept string, not time object
    """Send a reminder at a specific time."""
    user = User.query.get(user_id)
    if not user or not user.timezone:
        app.logger.warning(f"send_at: User {user_id} not found or has no timezone. Skipping.")
        return

    try:
        user_tz = pytz.timezone(user.timezone)
    except pytz.UnknownTimeZoneError:
        app.logger.error(f"send_at: User {user_id} has invalid timezone '{user.timezone}'. Skipping.")
        return

    now_in_user_tz = dt.now(user_tz)

    # Parse the time string
    try:
        reminder_time_struct = dt.strptime(reminder_time_str, '%H:%M').time()
    except Exception as e:
        app.logger.error(f"send_at: Invalid reminder_time_str '{reminder_time_str}' for user {user_id}: {e}")
        return

    target_time_in_user_tz = now_in_user_tz.replace(
        hour=reminder_time_struct.hour,
        minute=reminder_time_struct.minute,
        second=0,
        microsecond=0
    )
    app.logger.info(f"send_at: User {user_id} - Initial target time in user's timezone ({user.timezone}): {target_time_in_user_tz.strftime('%Y-%m-%d %H:%M:%S %Z%z')}") 


    if now_in_user_tz >= target_time_in_user_tz:
        # If the target time is in the past for today, schedule for tomorrow
        target_time_in_user_tz += timedelta(days=1)
        app.logger.info(f"send_at: User {user_id} - Target time was in the past for today. Adjusted to next day: {target_time_in_user_tz.strftime('%Y-%m-%d %H:%M:%S %Z%z')}")
    
    utc_target = target_time_in_user_tz.astimezone(pytz.utc)
    
    # Calculate countdown
    now_utc = dt.now(pytz.utc)
    countdown_seconds = (utc_target - now_utc).total_seconds()
    
    # Log scheduling details
    app.logger.info(
        f"send_at: User {user_id} - Scheduling 'send_meal_reminder_task'. "
        f"User's local target: {target_time_in_user_tz.strftime('%Y-%m-%d %H:%M')} {user.timezone}. "
        f"Scheduled UTC ETA: {utc_target.strftime('%Y-%m-%d %H:%M:%S %Z%z')}. "
        f"Countdown from server (UTC now): {countdown_seconds:.0f} seconds (approx {timedelta(seconds=countdown_seconds)})."
    )

    # Ensure send_meal_reminder_task is registered with Celery
    send_meal_reminder_task.apply_async(args=[user_id], eta=utc_target)

@celery.task(name='calorie_tracker.routes.send_meal_reminder_task')
def send_meal_reminder_task(user_id):
    """Celery task to send meal reminder notification."""
    app.logger.info(f"send_meal_reminder_task: Task started for user_id: {user_id}")
    with app.app_context(): 
        app.logger.info(f"send_meal_reminder_task: App context entered for user_id: {user_id}")
        user = User.query.get(user_id)
        if user:
            app.logger.info(f"send_meal_reminder_task: User {user.username} (ID: {user_id}) found.")
            if user.notify_meal_reminder:
                app.logger.info(f"send_meal_reminder_task: notify_meal_reminder is TRUE for user {user_id}.")
                try:
                    app.logger.info(f"send_meal_reminder_task: Attempting to send push notification to user {user_id}.")
                    send_push_notification(
                        user,
                        title="🍽️ Meal Reminder",
                        body="It's time to log your meals for today!",
                        url=url_for('saved')
                    )
                    app.logger.info(f"send_meal_reminder_task: Successfully called send_push_notification for user {user_id}.")
                except Exception as e:
                    app.logger.error(f"send_meal_reminder_task: Error calling send_push_notification for user {user_id}: {e}", exc_info=True)
            else:
                app.logger.info(f"send_meal_reminder_task: notify_meal_reminder is FALSE for user {user_id}. Notification not sent.")
        else:
            app.logger.warning(f"send_meal_reminder_task: User with ID {user_id} not found. Cannot send reminder.")
    app.logger.info(f"send_meal_reminder_task: Task finished for user_id: {user_id}")
