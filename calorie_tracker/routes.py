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

UPLOAD_FOLDER = './calorie_tracker/static/uploads/'
app.config['SECRET_KEY'] = 'ashdahdadss'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
openai.api_key=config.OPENAI_API_KEY

def read_image_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

@app.route('/')
def index():
    custom_calories = request.args.get('custom_calories', default=0, type=int)
    if custom_calories:
        push_data(custom_calories)
    return render_template('dashboard.html', year=dt.now().year, custom_calories=custom_calories)

@app.route('/saved')
def saved():
    # Simulate saved data
    saved_data = get_saved_data()
    return render_template('saved.html', saved_data=saved_data)


@app.route('/custom_calories', methods=['GET', 'POST'])
def custom_calories():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(url_for('custom_calories'))
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
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
        flash('Invalid file type')
        return redirect(url_for('custom_calories'))
    # GET request
    cleanup_uploads(app.config['UPLOAD_FOLDER'], max_age_seconds=86400)
    return render_template('custom_calories.html')

def get_saved_data():
    # Simulate saved data
    saved_data = [
        {"date": "2023-10-01", "calories": 2000},
        {"date": "2023-10-02", "calories": 1800},
        {"date": "2023-10-03", "calories": 2200},
    ]
    return saved_data

def push_data(calories):
    # Simulate pushing data to a database or API
    print(f"Pushing data: {calories} calories")
    flash('Data pushed successfully!')
    return redirect(url_for('index'))