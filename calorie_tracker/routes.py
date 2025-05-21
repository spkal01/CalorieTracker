import os
import re
import cv2
from datetime import datetime as dt, timedelta
from flask import flash, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from calorie_tracker import app, allowed_file, cleanup_uploads
import openai
import base64
from calorie_tracker import config
from flask_sqlalchemy import SQLAlchemy
from calorie_tracker import db
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from calorie_tracker import bcrypt
from calorie_tracker import login_manager
from flask_mail import Message
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.fileadmin import FileAdmin
from flask_admin import AdminIndexView
from wtforms import PasswordField
from calorie_tracker import mail
import random
from itsdangerous import URLSafeTimedSerializer


# Initialize SQLAlchemy

openai.api_key=config.OPENAI_API_KEY

def read_image_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')


class FoodItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    saved_calories_id = db.Column(db.Integer, db.ForeignKey('saved_calories.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    calories = db.Column(db.Integer, nullable=False)

class SavedCalories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_items = db.relationship(
        'FoodItem',
        backref='saved_calories',
        lazy=True,
        cascade="all, delete-orphan"
    )

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    age = db.Column(db.Integer, nullable=True)
    weight = db.Column(db.Float, nullable=True)
    height = db.Column(db.Float, nullable=True)
    daily_calorie_goal = db.Column(db.Integer, nullable=True)
    saved_calories = db.relationship('SavedCalories', backref='user', lazy=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class AdminUser(ModelView):

    column_exclude_list = ['password']
    form_excluded_columns = ['password']

    form_extra_fields = {
        'new_password': PasswordField('New Password')
    }

    def on_model_change(self, form, model, is_created):
        # If a new password is entered, hash and set it
        if form.new_password.data:
            model.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            db.session.commit()

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

class AdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

class FileAdminView(FileAdmin):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

@app.before_request
def require_login():
    public_routes = ['login', 'signup', 'static', 'signup_verify', 'signup_email', 'forgot_password', 'reset_password']  # Add other public endpoints if needed
    if not current_user.is_authenticated and request.endpoint not in public_routes:
        return redirect(url_for('login'))

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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('login/signup_step1.html')
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
    entry = SavedCalories.query.filter_by(date=today, user_id=current_user.id).first()
    if not entry or not entry.food_items:
        food_entries = {}
    else:
        food_entries = {food.name: food.calories for food in entry.food_items}

    # Compose the prompt for OpenAI
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