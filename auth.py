import re # email format check
import mysql.connector # to catch database error
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from .models import User
from .db import get_db_connection
from .security import hash_master_password, verify_master_password, generate_salt, derive_key
from datetime import date
from .error_manager import notify

auth = Blueprint('auth', __name__)

# something@something.something
EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


# ALWAYS logs the current browser out first and sends it to the Login page
# so opening the website always starts at Login / Sign Up
# (a new tab, refreshing the tab, coming back to it later)
# and you must type your master password again every time, even if you never pressed Logout
@auth.route('/')
def index():
    if current_user.is_authenticated:
        session.pop('vault_key', None) # forget this tab's decryption key
        logout_user() # end the Flask-Login session
    return redirect(url_for('auth.login'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', ' ')

        if not email or not password:
            notify('Please enter both your email and your master password.', 'Warning')
            return render_template("login.html", user=current_user)

        user = User.get_by_email(email)

        # One message for both cases, so nobody can use the login page to find out, which emails have an account.
        if user is None or not verify_master_password(password, user.master_password_hash):
            notify('Incorrect email or password, try again.', 'Warning',
                   detail=f'Failed login attempt for email: {email}')

        # uses the account_status column (Active / Locked) from the users table
        elif user.account_status == 'Locked':
            notify('This account is locked.', 'Warning', detail=f'Locked account tried to log in: {email}')

        # Get this user's salt from security_keys
        else:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT encryption_salt FROM security_keys WHERE user_id = %s", (user.id,))
            row = cursor.fetchone()
            cursor.close()
            conn.close()

            # without a salt the vault key cannot be made, so do not log the user in half-way
            if row is None:
                notify('Your encryption data is missing, so the vault cannot be opened.', 'Critical',
                       detail=f'No security_keys row for user id {user.id}')
                return render_template("login.html", user=current_user)

            # remember=False
            # The vault key only exists while the session exists, so a "remember me" cookie would log the user in without a key.
            login_user(user, remember=False)

            # Derive the vault encryption key for this session (never saved in the database)
            key = derive_key(password, row['encryption_salt'])
            session['vault_key'] = key.hex()

            notify('Logged in successfully!', 'Info', detail=f'User {user.id} logged in')
            return redirect(url_for('views.home'))

    return render_template("login.html", user=current_user)


@auth.route('/log-out')
@login_required
def log_out():
    session.pop('vault_key', None)
    logout_user()
    notify('You have been logged out.', 'Info')
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email', ' ').strip().lower()
        first_name = request.form.get('first_name', ' ').strip()
        # print(repr(first_name), len(first_name))
        password1 = request.form.get('password1', ' ')
        password2 = request.form.get('password2', ' ')

        existing_user = User.get_by_email(email)

        # check if all the account information is valid
        # every failed check is a 'Warning' and the user stays on the sign-up page
        if existing_user:
            notify('Email already exists.', 'Warning')
        elif not EMAIL_PATTERN.match(email):
            notify('Please enter a valid email address.', 'Warning')
        elif len(first_name) < 2:
            notify('First name must be at least 2 characters.', 'Warning')
        elif password1 != password2:
            notify("Passwords don't match.", 'Warning')
        elif len(password1) < 7:
            notify('Password must be at least 7 characters.', 'Warning')
        else:
            # add user to database
            hashed_password = hash_master_password(password1)
            salt = generate_salt()

            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (email, first_name, master_password_hash) VALUES (%s, %s, %s)",
                    (email, first_name, hashed_password)
                )
                new_user_id = cursor.lastrowid
                cursor.execute(
                    "INSERT INTO security_keys (user_id, encryption_salt, last_rotation) VALUES (%s, %s, %s)",
                    (new_user_id, salt, date.today())
                )
                conn.commit()
                cursor.close()
            except mysql.connector.Error as e:
                if conn:
                    conn.rollback()
                notify('Could not create your account. Please try again.', 'Critical',
                       detail=f'Sign-up database error: {e}')
                return render_template('sign_up.html', user=current_user)
            finally:
                if conn:
                    conn.close()

            new_user = User.get(new_user_id)
            login_user(new_user, remember=False)

            key = derive_key(password1, salt)
            session['vault_key'] = key.hex()

            notify('Account created!', 'Info', detail=f'New account created, user id {new_user_id}')
            return redirect(url_for('views.home'))

    return render_template('sign_up.html', user=current_user)