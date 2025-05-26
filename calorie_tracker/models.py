from flask_login import UserMixin
from calorie_tracker import db
import enum
from sqlalchemy import Date
from datetime import date 

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

    # Add this relationship for the diet plan
    diet_days = db.relationship('UserDietDay', backref='user', lazy='dynamic', cascade="all, delete-orphan")

    # New fields for rate limiting diet plan generation
    last_plan_generation_date = db.Column(db.Date, nullable=True)
    plan_generations_today = db.Column(db.Integer, default=0, nullable=False)

    # New fields for tracking diet plan generation status
    active_diet_generation_token = db.Column(db.String(32), nullable=True, index=True)
    last_diet_generation_status = db.Column(db.String(20), nullable=True) # e.g., "pending", "completed", "failed"

# Add these Enums
class DayOfWeekEnum(enum.Enum):
    MONDAY = "Monday"
    TUESDAY = "Tuesday"
    WEDNESDAY = "Wednesday"
    THURSDAY = "Thursday"
    FRIDAY = "Friday"
    SATURDAY = "Saturday"
    SUNDAY = "Sunday"

class MealTypeEnum(enum.Enum):
    BREAKFAST = "Breakfast"
    MID_MORNING_SNACK = "Mid-Morning Snack"
    LUNCH = "Lunch"
    AFTERNOON_SNACK = "Afternoon Snack"
    DINNER = "Dinner"
    EVENING_SNACK = "Evening Snack" # Optional: for more flexibility

class UserDietDay(db.Model):
    __tablename__ = 'user_diet_day'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day_of_week = db.Column(db.Enum(DayOfWeekEnum), nullable=False)

    # Relationship to meals for this specific day and user
    meals = db.relationship('Meal', backref='user_diet_day', lazy='dynamic', cascade="all, delete-orphan")

    # Ensure a user has only one diet plan entry per day_of_week
    __table_args__ = (db.UniqueConstraint('user_id', 'day_of_week', name='_user_day_of_week_uc'),)

    def __repr__(self):
        return f"<UserDietDay UserID: {self.user_id} Day: {self.day_of_week.value}>"

class Meal(db.Model):
    __tablename__ = 'meal'
    id = db.Column(db.Integer, primary_key=True)
    user_diet_day_id = db.Column(db.Integer, db.ForeignKey('user_diet_day.id'), nullable=False)
    meal_type = db.Column(db.Enum(MealTypeEnum), nullable=False)

    # Relationship to individual food items in this meal
    meal_items = db.relationship('MealItem', backref='meal', lazy='dynamic', cascade="all, delete-orphan")

    # Ensure a UserDietDay has only one of each meal_type (e.g., one Breakfast per Monday plan)
    __table_args__ = (db.UniqueConstraint('user_diet_day_id', 'meal_type', name='_diet_day_meal_type_uc'),)

    def __repr__(self):
        return f"<Meal DietDayID: {self.user_diet_day_id} Type: {self.meal_type.value}>"

class MealItem(db.Model):
    __tablename__ = 'meal_item'
    id = db.Column(db.Integer, primary_key=True)
    meal_id = db.Column(db.Integer, db.ForeignKey('meal.id'), nullable=False)
    food_name = db.Column(db.String(200), nullable=False)
    calories = db.Column(db.Integer, nullable=True)  # Planned calories
    quantity = db.Column(db.String(100), nullable=True) # e.g., "1 cup", "100g"
    notes = db.Column(db.Text, nullable=True) # Optional notes for the item

    def __repr__(self):
        return f"<MealItem Name: {self.food_name}>"

