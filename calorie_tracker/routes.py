import os
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
    # Clean up old files (optional, e.g., files older than 1 day)
    cleanup_uploads(app.config['UPLOAD_FOLDER'], max_age_seconds=86400)
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
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
                                {"type": "input_text", "text": "Please analyze this image and provide the calorie count."},
                                {"type": "input_image", "image_url": f"data:image/png;base64,{image_base64}"},
                            ],
                        }
                    ],
                )

                ai_result = response.output_text
            except:
                ai_result = "Some error occured try again"

            return render_template('index.html', img_path=file_path, ai_result=ai_result)
    flash('Invalid file type')
    return redirect(url_for('index'))