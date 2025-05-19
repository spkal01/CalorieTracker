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
    
class SavedCalories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(50), nullable=False)
    calories = db.Column(db.Integer, nullable=False)

@app.route('/')
def index():
    custom_calories = request.args.get('calories', default=0, type=int)
    if custom_calories:
        push_data(custom_calories)
    return render_template('dashboard.html', year=dt.now().year, custom_calories=custom_calories)

@app.route('/saved', methods=['GET', 'POST'])
def saved():
    # Simulate saved data
    if request.method == 'POST':
        # Handle form submission
        date = request.form.get('date')
        calories = request.form.get('calories')
        if date and calories:
            # Save the data to the database
            push_data(calories, date)
            flash('Data saved successfully!', 'success')
        else:
            flash('Please provide both date and calories.', 'error')
    saved_data = get_saved_data()
    return render_template('saved.html', saved_data=saved_data)


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
                                    {"type": "input_text", "text": "Please analyze this image and provide the calorie count. The first integer in the response should be the calorie count."},
                                    {"type": "input_image", "image_url": f"data:image/png;base64,{image_base64}"},
                                ],
                            }
                        ],
                    )

                    ai_result = response.output_text
                    # Extract calorie value (first integer found in the response)
                    match = re.search(r'(\d+)\s*(?:kcal|calories|calorie)?', ai_result, re.IGNORECASE)
                    calories = int(match.group(1)) if match else None
                    print(f"Calories: {calories}")
                except:
                    ai_result = "Some error occured try again"
                    calories = None

                return render_template('custom_calories.html', img_path=file_path, ai_result=ai_result, calories=calories)
        flash('Invalid file type', 'error')
        return redirect(url_for('custom_calories'))
    # GET request
    cleanup_uploads(app.config['UPLOAD_FOLDER'], max_age_seconds=86400)
    return render_template('custom_calories.html')

def get_saved_data():
    # Simulate saved data
    saved_data = SavedCalories.query.all()
    if not saved_data:
        return []
    saved_data = [{'date': data.date, 'calories': data.calories} for data in saved_data]
    # Sort by date
    saved_data.sort(key=lambda x: dt.strptime(x['date'], "%Y-%m-%d"), reverse=True)
    return saved_data

def push_data(calories, date=dt.now().strftime("%Y-%m-%d")):
    existing_data = SavedCalories.query.filter_by(date=date).first()
    if existing_data:
        # Add to existing calories for that date
        existing_data.calories = int(existing_data.calories) + int(calories)
        db.session.commit()
    else:
        data = SavedCalories(date=date, calories=calories)
        db.session.add(data)
        db.session.commit()

def delete_data(date):
    # Delete the record with the given date
    data = SavedCalories.query.filter_by(date=date).first()
    if data:
        db.session.delete(data)
        db.session.commit()
        flash('Data deleted successfully!', 'success')
    else:
        flash('No data found for the given date.', 'error')
    return redirect(url_for('saved'))