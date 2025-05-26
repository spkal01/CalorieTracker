import os
import re
import random
import base64
import cv2
import secrets
import json
from datetime import datetime as dt

from flask import (
    flash, render_template, request, redirect, url_for, session, jsonify
)
from werkzeug.utils import secure_filename

from calorie_tracker import (
    app, allowed_file, cleanup_uploads, config, db, bcrypt, login_manager, mail
)

from calorie_tracker.models import (
    User, FoodItem, SavedCalories, # Keep existing
    UserDietDay, Meal, MealItem, DayOfWeekEnum, MealTypeEnum # Add new models and enums
)

from flask_sqlalchemy import SQLAlchemy
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


# Initialize SQLAlchemy

openai.api_key=config.OPENAI_API_KEY

def read_image_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

@app.before_request
def require_login():
    public_routes = [
        'login', 'signup', 'static', 'signup_verify', 'signup_email',
        'forgot_password', 'reset_password', 'landing',
        'login_google', 'google.login', 'google.authorized'
    ]  # Add other public endpoints if needed
    if not current_user.is_authenticated and request.endpoint not in public_routes:
        return redirect(url_for('landing'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
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
    return render_template('dashboard.html', year=dt.now().year)

@app.route('/saved', methods=['GET', 'POST'])
@login_required
def saved():
    if request.method == 'POST':
        date = request.form.get('date')
        food_name = request.form.get('food_name')
        food_calories = request.form.get('food_calories')
        if date and food_name and food_calories:
            entry = SavedCalories.query.filter_by(date=date, user_id=current_user.id).first()
            if not entry:
                entry = SavedCalories(date=date, user_id=current_user.id)
                db.session.add(entry)
                db.session.commit()
            food = FoodItem(saved_calories_id=entry.id, name=food_name, calories=int(food_calories))
            db.session.add(food)
            db.session.commit()
            flash('Food item added successfully!', 'success')
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
            filename = secure_filename(file.filename)
            dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
            filename = dt_now + ".jpg"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Process the image
            img = cv2.imread(file_path)
            if img is not None:
                # Convert image to Base64
                image_base64 = read_image_base64(file_path)

                try:

                    # Prepare GPT-4 Vision request
                    response =  openai.responses.create(
                        model="gpt-4o-mini",
                        input=[
                            {
                                "role": "user",
                                "content": [
                                    {"type": "input_text", "text": "Please analyze this image and provide the calorie count. The first integer in the response should be the calorie count. You should always start with the phrase 'The food item you uploaded is name' Replace name with the actual food name."},
                                    {"type": "input_text", "text": "Please provide the calorie count in kcal."},
                                    {"type": "input_text", "text": "Dont provide any unrelated information."},
                                    {"type": "input_text", "text": "Dont say anything like you cant know calories for sure just provide the best guess."},
                                    {"type": "input_image", "image_url": f"data:image/png;base64,{image_base64}"},
                                ],
                            }
                        ],
                        temperature=0,
                    )

                    ai_result = response.output_text
                    # Extract calorie value (first integer found in the response)
                    match = re.search(r'(\d+)\s*(?:kcal|calories|calorie)?', ai_result, re.IGNORECASE)
                    calories = int(match.group(1)) if match else None

                    # Extract food name from the phrase "The food item you uploaded is name"
                    name_match = re.search(r"The food item you uploaded is ([\w\s\-']+)", ai_result, re.IGNORECASE)
                    food_name = name_match.group(1).strip() if name_match else "Unknown"

                    print(f"Food: {food_name}, Calories: {calories}")
                except:
                    ai_result = "Some error occured try again"
                    calories = None
                    food_name = "Unknown"

                return render_template('custom_calories.html', img_path=file_path, ai_result=ai_result, calories=calories, food_name=food_name)
        flash('Invalid file type', 'error')
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
            'total_calories': total_calories
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
            daily_calorie_goal = request.form.get('daily_calorie_goal')
            if daily_calorie_goal:
                current_user.daily_calorie_goal = int(daily_calorie_goal)
                db.session.commit()
                flash('Daily calorie goal updated!', 'success')
            else:
                flash('Please provide a valid calorie goal.', 'error')
            age = request.form.get('age')
            weight = request.form.get('weight')
            height = request.form.get('height')
            gender = request.form.get('gender')
            if age and weight and height and gender:
                current_user.age = int(age)
                current_user.weight = float(weight)
                current_user.height = float(height)
                current_user.gender = str(gender)
                db.session.commit()
                flash('Profile updated!', 'success')
            else:
                flash('Please provide valid age, weight, and height.', 'error')
    return render_template(
        'settings.html',
        daily_calorie_goal=current_user.daily_calorie_goal,
        age=current_user.age,
        weight=current_user.weight,
        height=current_user.height,
        gender=current_user.gender,
        ai_suggestion=ai_suggestion
    )

def push_data(calories, date=dt.now().strftime("%Y-%m-%d"), food_name="Custom"):
    entry = SavedCalories.query.filter_by(date=date, user_id=current_user.id).first()
    if not entry:
        entry = SavedCalories(date=date, user_id=current_user.id)
        db.session.add(entry)
        db.session.commit()
    food = FoodItem(saved_calories_id=entry.id, name=food_name, calories=int(calories))
    db.session.add(food)
    db.session.commit()

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
    calories_consumed = sum(f.calories for f in entry.food_items) if entry else 0
    if current_user.daily_calorie_goal is None:
        flash('Please set your daily calorie goal in settings.', 'warning')
        return redirect(url_for('settings'))
    daily_calorie_goal = current_user.daily_calorie_goal or 2000  # fallback value
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

@app.route('/api/ai-analysis')
@login_required
def api_ai_analysis():
    analysis = get_ai_analysis()  # This returns markdown
    return jsonify({'analysis': analysis})

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

def ai_reccomend_daily_calories():
    age = current_user.age
    weight = current_user.weight
    height = current_user.height
    if not all([age, weight, height]):
        flash('Please provide your age, weight, and height in settings.', 'warning')
        return redirect(url_for('settings'))


    response = openai.chat.completions.create(
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
        temperature=0
    )

    return response.choices[0].message.content

def get_ai_analysis():
    weight = current_user.weight
    height = current_user.height
    age = current_user.age
    gender = current_user.gender
    calorie_goal = current_user.daily_calorie_goal
    if not all([weight, height, age, gender, calorie_goal]):
        flash('Please set your profile information in settings.', 'error')
        return redirect(url_for('settings'))

    today = dt.now().strftime("%Y-%m-%d")
    now_time = dt.now().strftime("%H:%M")
    total_calories = get_saved_data()[0]['total_calories'] if get_saved_data() else 0
    entry = SavedCalories.query.filter_by(date=today, user_id=current_user.id).first()
    # --- Caching logic using session ---
    cache_key = f"ai_analysis_{today}_{current_user.id}"
    cache_cal_key = f"ai_analysis_cal_{today}_{current_user.id}"
    cached_analysis = session.get(cache_key)
    cached_calories = session.get(cache_cal_key)

    if cached_analysis and cached_calories == total_calories:
        return cached_analysis

    # Compose the prompt for OpenAI
    food_entries = {food.name: food.calories for food in entry.food_items} if entry and entry.food_items else {}

    prompt = (
        f"You are a helpful nutrition assistant. "
        f"Here is today's user data:\n"
        f"- Date: {today}\n"
        f"- Time: {now_time}\n"
        f"- Age: {age}\n"
        f"- Weight: {weight} kg\n"
        f"- Height: {height} cm\n"
        f"- Gender: {gender}\n"
        f"- Daily Calorie Goal: {calorie_goal} kcal\n"
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

    response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful nutrition and calorie tracking assistant."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.7,
        max_tokens=400
    )
    analysis = response.choices[0].message.content

    # Cache the analysis and calories
    session[cache_key] = analysis
    session[cache_cal_key] = total_calories

    return analysis
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
    db.create_all()
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
    login_user(user)
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
    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful nutrition assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.7
        )
        ai_content = response.choices[0].message.content.strip()
        # Optionally log/print for debugging
        if app.debug:
            print("AI response:", ai_content)
        match = re.search(r'(\[.*\])', ai_content, re.DOTALL)
        if match:
            foods = json.loads(match.group(1))
        else:
            foods = []
            flash('Could not extract foods from AI response.', 'error')
    except Exception as e:
        if app.debug:
            print("OpenAI/JSON error:", e)
            foods = []
        flash('Could not analyze meal. Please try again.', 'error')

    # Save each food item to the user's current day
    today = dt.now().strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(date=today, user_id=current_user.id).first()
    if not entry:
        entry = SavedCalories(date=today, user_id=current_user.id)
        db.session.add(entry)
        db.session.commit()
    for food in foods:
        name = food.get('name')
        calories = food.get('calories')
        if name and calories:
            db.session.add(FoodItem(saved_calories_id=entry.id, name=name, calories=int(calories)))
    db.session.commit()
    if foods:
        flash('Meal analyzed and foods added!', 'success')
    return redirect(url_for('saved'))


@app.route('/api/add_diet_food', methods=['POST'])
@login_required # Ensure @login_required if it wasn't already
def api_diet_plan(): # Renaming to api_add_diet_food for clarity if you prefer
    data = request.json
    if not data or 'food_name' not in data or 'calories' not in data: # Ensure calories are present
        return jsonify({'error': 'Invalid input, food_name and calories required'}), 400
    
    food_name = data['food_name']
    calories = data.get('calories', 0) # Default to 0 if not provided, though frontend sends it

    if not isinstance(food_name, str) or not isinstance(calories, int):
        return jsonify({'error': 'Invalid data format for food_name or calories'}), 400

    today_date_str = dt.now().strftime("%Y-%m-%d")
    entry = SavedCalories.query.filter_by(date=today_date_str, user_id=current_user.id).first()
    if not entry:
        entry = SavedCalories(date=today_date_str, user_id=current_user.id)
        db.session.add(entry)
        # Commit here or after adding food item, depending on preference for atomicity
        # For simplicity, committing after adding food item is fine.
    
    # Check if this food item already exists for this entry to prevent duplicates if re-clicked without un-striking
    existing_food_item = FoodItem.query.filter_by(saved_calories_id=entry.id, name=food_name).first()
    if not existing_food_item:
        food = FoodItem(saved_calories_id=entry.id, name=food_name, calories=int(calories))
        db.session.add(food)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Food item added'}), 200
    else:
        # Item already logged for today, consider it a successful "mark as done" if it wasn't already.
        # No change needed in DB if it's already there.
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
    

def get_diet_plan(describe_diet=''):
    """
    Fetches the user's diet plan. If none exists, generates a sample one.
    Returns the plan structured as a dictionary:
    { day_name: { meal_type_name: [meal_items] } }
    """
    user = current_user
    plan_data = {}

    # Check if any diet days exist for the user
    user_has_plan = UserDietDay.query.filter_by(user_id=user.id).first()

    if not user_has_plan or describe_diet != '':
        generate_and_store_diet_plan(user.id, describe_diet)

    diet_days_for_user = UserDietDay.query.filter_by(user_id=user.id).order_by(UserDietDay.day_of_week).all()

    for diet_day in diet_days_for_user:
        day_name = diet_day.day_of_week.value # e.g., "Monday"
        plan_data[day_name] = {}
        
        meals_for_day = Meal.query.filter_by(user_diet_day_id=diet_day.id).order_by(Meal.meal_type).all()
        for meal in meals_for_day:
            meal_type_name = meal.meal_type.value # e.g., "Breakfast"
            
            items_for_meal = MealItem.query.filter_by(meal_id=meal.id).all()
            plan_data[day_name][meal_type_name] = [
                {
                    "id": item.id, # Good to have for potential future interactions (edit/delete item)
                    "food_name": item.food_name,
                    "calories": item.calories,
                    "quantity": item.quantity,
                    "notes": item.notes
                } for item in items_for_meal
            ]
    return plan_data

@app.route('/create_diet_plan', methods=['GET', 'POST'])
@login_required
def create_diet_plan():
    current_weekday = dt.now().strftime("%A")
    plan = get_diet_plan()  
    if request.method == 'POST':
        describe_diet = request.form.get('describe_diet')
        if describe_diet:
            plan = get_diet_plan(describe_diet)
            return render_template('create_diet_plan.html', current_day_name=current_weekday, diet_plan=plan)
        else:
            flash('Please describe your diet plan if you want to generate a new one.', 'error')
            return redirect(url_for('create_diet_plan'))

    # For GET request
    return render_template('create_diet_plan.html', current_day_name=current_weekday, diet_plan=plan)


def generate_and_store_diet_plan(user_id, describe_diet=''):
    user = User.query.get(user_id) # Fetch user to get their details
    if not user:
        print(f"User with ID {user_id} not found.")
        return False

    calorie_goal = user.daily_calorie_goal
    weight = user.weight
    height = user.height
    age = user.age
    gender = user.gender

    if not all([calorie_goal, weight, height, age, gender]):
        print(f"User {user_id} is missing some profile details (calorie goal, weight, height, age, or gender). Cannot generate AI plan accurately.")
        flash('Please complete your profile in settings before generating a diet plan.', 'error')
        redirect(url_for('settings'))
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

    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[
                {"role": "system", "content": "You are a diet planning assistant that outputs JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        ai_generated_plan_str = response.choices[0].message.content
        parsed_plan = json.loads(ai_generated_plan_str)
    except json.JSONDecodeError as e:
        print(f"Error: AI did not return valid JSON. {e}")
        print(f"AI response string: {ai_generated_plan_str}")
        return False # Indicate failure
    except Exception as e:
        print(f"Error calling OpenAI API: {e}")
        return False # Indicate failure

    if not parsed_plan:
        print("AI returned an empty plan.")
        return False

    # Clear existing diet plan for the user
    # This is a more thorough way to delete to ensure related items are handled
    # if cascade delete is not perfectly configured.
    try:
        old_diet_days = UserDietDay.query.filter_by(user_id=user_id).all()
        for old_day in old_diet_days:
            old_meals = Meal.query.filter_by(user_diet_day_id=old_day.id).all()
            for old_meal in old_meals:
                MealItem.query.filter_by(meal_id=old_meal.id).delete(synchronize_session=False)
            Meal.query.filter_by(user_diet_day_id=old_day.id).delete(synchronize_session=False)
        UserDietDay.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    except Exception as e:
        db.session.rollback()
        print(f"Error clearing old diet plan: {e}")
        return False

    DAY_NAME_TO_ENUM = {day.value: day for day in DayOfWeekEnum}
    MEAL_TYPE_TO_ENUM = {meal.value: meal for meal in MealTypeEnum}

    try:
        for day_name_str, meals_data in parsed_plan.items():
            day_enum = DAY_NAME_TO_ENUM.get(day_name_str)
            if not day_enum:
                print(f"Warning: Unknown day name '{day_name_str}' in AI plan. Skipping.")
                continue

            diet_day = UserDietDay(user_id=user_id, day_of_week=day_enum)
            db.session.add(diet_day)
            if not isinstance(meals_data, dict):
                print(f"Warning: Expected a dictionary for meals in '{day_name_str}', got {type(meals_data)}. Skipping day.")
                continue

            for meal_type_str, items_data in meals_data.items():
                meal_type_enum = MEAL_TYPE_TO_ENUM.get(meal_type_str)
                if not meal_type_enum:
                    print(f"Warning: Unknown meal type '{meal_type_str}' for '{day_name_str}'. Skipping meal.")
                    continue
                
                meal = Meal(user_diet_day=diet_day, meal_type=meal_type_enum)
                db.session.add(meal)

                if not isinstance(items_data, list):
                    print(f"Warning: Expected a list for items in '{meal_type_str}' for '{day_name_str}', got {type(items_data)}. Skipping meal.")
                    continue

                for item_dict in items_data:
                    if not isinstance(item_dict, dict):
                        print(f"Warning: Expected a dictionary for a meal item, got {type(item_dict)}. Skipping item.")
                        continue

                    food_name = item_dict.get('food_name')
                    calories_val = item_dict.get('calories')
                    quantity = item_dict.get('quantity')
                    notes = item_dict.get('notes', '') # Default to empty string

                    if not food_name or food_name.strip() == "":
                        print(f"Warning: Skipping item due to missing or empty food_name: {item_dict}")
                        continue
                    if calories_val is None:
                        print(f"Warning: Skipping item '{food_name}' due to missing calories.")
                        continue
                    
                    try:
                        calories = int(calories_val)
                    except (ValueError, TypeError):
                        print(f"Warning: Skipping item '{food_name}' due to invalid calorie format: {calories_val}")
                        continue
                    
                    meal_item = MealItem(
                        meal=meal, # Associate with the meal object
                        food_name=food_name.strip(),
                        calories=calories,
                        quantity=quantity.strip() if quantity else None,
                        notes=notes.strip() if notes else None
                    )
                    db.session.add(meal_item)
        
        db.session.commit()
        print(f"Successfully generated and stored AI diet plan for user {user_id}.")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Error processing AI plan and saving to DB: {e}")
        import traceback
        traceback.print_exc()
        return False
