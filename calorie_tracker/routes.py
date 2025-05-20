import os
import re
import cv2
from datetime import datetime as dt
from flask import flash, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from calorie_tracker import app, allowed_file, cleanup_uploads
import openai
import base64
from calorie_tracker import config
from flask_sqlalchemy import SQLAlchemy
from calorie_tracker import db

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
    food_items = db.relationship(
        'FoodItem',
        backref='saved_calories',
        lazy=True,
        cascade="all, delete-orphan"
    )

@app.route('/')
def index():
    custom_calories = request.args.get('calories', default=0, type=int)
    food_name = request.args.get('food_name', default='', type=str)
    if custom_calories and food_name:
        push_data(custom_calories, food_name=food_name)
        return redirect(url_for('saved'))
    return render_template('dashboard.html', year=dt.now().year)

@app.route('/saved', methods=['GET', 'POST'])
def saved():
    if request.method == 'POST':
        date = request.form.get('date')
        food_name = request.form.get('food_name')
        food_calories = request.form.get('food_calories')
        if date and food_name and food_calories:
            # Find or create SavedCalories for the date
            entry = SavedCalories.query.filter_by(date=date).first()
            if not entry:
                entry = SavedCalories(date=date)
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
def add_food(entry_id):
    name = request.form.get('food_name')
    calories = request.form.get('food_calories')
    if name and calories:
        food = FoodItem(saved_calories_id=entry_id, name=name, calories=int(calories))
        db.session.add(food)
        db.session.commit()
        flash('Food item added!', 'success')
    else:
        flash('Please provide both food name and calories.', 'error')
    return redirect(url_for('saved'))

def get_saved_data():
    saved_data = SavedCalories.query.all()
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

def push_data(calories, date=dt.now().strftime("%Y-%m-%d"), food_name="Custom"):
    entry = SavedCalories.query.filter_by(date=date).first()
    if not entry:
        entry = SavedCalories(date=date)
        db.session.add(entry)
        db.session.commit()
    # Always add a new FoodItem for this entry
    food = FoodItem(saved_calories_id=entry.id, name=food_name, calories=int(calories))
    db.session.add(food)
    db.session.commit()

@app.route('/delete/<int:entry_id>', methods=['POST'])
def delete_data(entry_id):
    data = SavedCalories.query.get(entry_id)
    if data:
        db.session.delete(data)
        db.session.commit()
        flash('Data deleted successfully!', 'success')
    else:
        flash('No data found for the given entry.', 'error')
    return redirect(url_for('saved'))

@app.route('/edit/<int:entry_id>', methods=['POST'])
def edit_data(entry_id):
    data = SavedCalories.query.get(entry_id)
    new_calories = request.form.get('calories')
    if data and new_calories:
        data.calories = new_calories
        db.session.commit()
        flash('Data updated successfully!', 'success')
    else:
        flash('No data found for the given entry.', 'error')
    return redirect(url_for('saved'))