from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.fileadmin import FileAdmin
from flask_admin import AdminIndexView
from flask_login import current_user
from flask import redirect, url_for, request
from wtforms import PasswordField

from calorie_tracker import db, bcrypt
from calorie_tracker.models import User

class AdminUser(ModelView):
    column_exclude_list = ['password']
    form_excluded_columns = ['password']

    form_extra_fields = {
        'new_password': PasswordField('New Password')
    }

    def on_model_change(self, form, model, is_created):
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