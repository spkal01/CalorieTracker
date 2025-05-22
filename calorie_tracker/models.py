from flask_login import UserMixin
from calorie_tracker import db

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