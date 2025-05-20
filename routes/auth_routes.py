from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from models import db, User
import re
#python app.py TO GET TO THE WEBSITE AHHHHHHHHHHHH
auth_bp = Blueprint('auth_bp', __name__)

is_valid_username = lambda username: bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,19}$', username))
is_valid_password = lambda password: bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$', password))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']# if not is_valid_username(username):
        password = request.form['password']

        # Vulnerable to SQL Injection due to string formatting
        # Intentionally insecure: Using raw string formatting instead of parameterized queries
        user = User.query.filter_by(username=username).first()

        if user and user.verify_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('task_bp.dashboard'))
        else:
            flash('Invalid credentials! Please try again.')

    return render_template('login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # No input validation for username/password (intentionally insecure)
        # No password strength requirements (intentionally insecure)

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists!')
            return redirect(url_for('auth_bp.register'))
        if not is_valid_username(username):
            flash('Must start with a letter, can include, numbers, underscore and hyphens')
            return redirect(url_for('auth_bp.registers'))

        new_user = User(username=username)
        new_user.set_password(password) # use the method to set hashed password
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('auth_bp.login'))

    return render_template('register.html')


@auth_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('auth_bp.login'))