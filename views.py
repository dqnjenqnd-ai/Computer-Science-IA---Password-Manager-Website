import time
from functools import wraps
import mysql.connector
from flask import Blueprint, render_template, request, redirect, url_for, session
from flask_login import login_required, current_user, logout_user
from .db import get_db_connection
from .security import encrypt_password, decrypt_password, update_checksum, verify_checksum
from .error_manager import notify
import json

views = Blueprint('views', __name__)

MAX_LEN = 255 # website_name / account_username / account_email are varchar(255)


# Password Retrieval & Organisation:
#   the sort choices offered on the main page
# The user's choice is looked up in this dictionary, so only these exact ORDER BY texts can ever reach the SQL query
# (this protects against SQL injection through the sort menu)
SORT_OPTIONS = {
    'newest': 'created_at DESC', # "Sort passwords (Newest to Oldest)"
    'oldest': 'created_at ASC',
    'az': 'website_name ASC',
    'za': 'website_name DESC',
}

# Helper functions used by the routes below
def vault_required(f):
    """[NEW] Pages that decrypt or encrypt need the vault key that login stored in the session.
    If it is missing (e.g. the session expired) the user is sent back to log in again."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'vault_key' not in session:
            logout_user()
            notify('Your vault session expired. Please log in again.', 'Warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)

    return wrapper


def get_vault_key():
    return bytes.fromhex(session['vault_key'])


def run_write(sql, params):
    """[NEW] Runs one INSERT / UPDATE / DELETE, commits, and returns how many rows changed."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_entry(entry_id):
    """[NEW] Loads ONE entry, but only if it belongs to the logged-in user
    (Success criterion 9: users can never see other users' passwords)."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM credentials WHERE id = %s AND user_id = %s",
        (entry_id, current_user.id)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row


def read_form():
    """[NEW] Reads the add/edit form. The password is NOT stripped because spaces can be
    a real part of a password."""
    return (
        request.form.get('website_name', '').strip(),
        request.form.get('account_username', '').strip(),
        request.form.get('account_email', '').strip(),
        request.form.get('password', ''),
        request.form.get('note', '').strip(),
    )


def validate_entry(website_name, account_username, account_email, password):
    """[NEW] Password Management: input validation.
    Returns an error text, or None if everything is valid. (Success criterion 7)"""
    if not website_name:
        return 'Website name cannot be empty.'
    if not password:
        return 'Password cannot be empty.'
    if not account_username and not account_email:
        return 'Enter a username or an email for this account.'
    if account_email and '@' not in account_email:
        return 'Enter a valid email address.'
    if max(len(website_name), len(account_username), len(account_email)) > MAX_LEN:
        return 'Website, username and email must be 255 characters or fewer.'
    return None


def check_integrity():
    """[NEW] The 'Checksum Match?' decision from the flowchart. Shows a Critical message if the
    credentials table was changed outside the app. (Test #6 and Test #11)"""
    try:
        if not verify_checksum():
            notify('Integrity check failed: stored data was changed outside this app.', 'Critical')
    except mysql.connector.Error as e:
        notify('Could not run the integrity check.', 'Critical', detail=f'Integrity check database error: {e}')


"""
MAIN PAGE  =  Password Retrieval & Organisation (search + sort)
"""

@views.route('/')
@login_required
def home():
    start = time.perf_counter() # to prove the "under 3 seconds" criterion
    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'newest')
    if sort not in SORT_OPTIONS:
        sort = 'newest'
    order_by = SORT_OPTIONS[sort]

    check_integrity()

    rows = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # The main page lists entries WITHOUT decrypting anything:
        # passwords are only decrypted on the View / Edit pages
        # This keeps the page fast and keeps plaintext off the screen.
        cursor.execute(
            "SELECT id, website_name, account_username, account_email, created_at "
            "FROM credentials WHERE user_id = %s AND website_name LIKE %s "
            f"ORDER BY {order_by}",
            (current_user.id, f'%{search}%')  # %text% = website name CONTAINS the search text
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
    except mysql.connector.Error as e:
        notify('Could not load your passwords.', 'Critical', detail=f'Main page database error: {e}')

    load_time = time.perf_counter() - start
    if load_time > 3:
        notify(f'The main page took {load_time:.1f} seconds to load.', 'Warning')

    return render_template('home.html', user=current_user, credentials=rows,
                           search=search, sort=sort, load_time=load_time)


"""
ADD PASSWORD PAGE  =  Password Management (create)
"""
@views.route('/add', methods=['GET', 'POST'])
@login_required
@vault_required
def add_password():
    if request.method == 'POST':
        website_name, account_username, account_email, plain_password, note = read_form()

        error = validate_entry(website_name, account_username, account_email, plain_password)
        if error:
            notify(error, 'Warning')  # user stays on the form
            return render_template('password_form.html', user=current_user, mode='add', form=request.form)

        # Encrypt BEFORE saving: only ciphertext ever reaches the database
        ciphertext = encrypt_password(plain_password, get_vault_key())

        try:
            run_write(
                "INSERT INTO credentials (user_id, website_name, account_username, account_email, "
                "encrypted_password, note) VALUES (%s, %s, %s, %s, %s, %s)",
                (current_user.id, website_name, account_username or None, account_email or None,
                 ciphertext, note or None)
            )
            update_checksum()  # keep the integrity digest current
        except mysql.connector.Error as e:
            notify('The entry could not be saved because of a database error.', 'Critical',
                   detail=f'Add entry failed: {e}')
            return render_template('password_form.html', user=current_user, mode='add', form=request.form)

        notify('Entry added!', 'Info')
        return redirect(url_for('views.home'))

    return render_template('password_form.html', user=current_user, mode='add', form={})


"""
VIEW PASSWORD PAGE  =  Encryption / Decryption (decrypt for display only)
"""
@views.route('/view/<int:entry_id>')
@login_required
@vault_required
def view_password(entry_id):
    check_integrity()

    entry = get_entry(entry_id)
    if entry is None:
        notify('Entry not found.', 'Warning')
        return redirect(url_for('views.home'))

    try:
        # Decrypted only for this page and never saved anywhere
        entry['decrypted_password'] = decrypt_password(entry['encrypted_password'], get_vault_key())
    except ValueError:
        # Wrong key, corrupted or tampered ciphertext
        notify('This entry could not be decrypted. It may be corrupted or have been tampered with.',
               'Critical', detail=f'Decryption failed for entry id {entry_id}')
        return redirect(url_for('views.home'))

    return render_template('view_password.html', user=current_user, entry=entry)


"""
EDIT PASSWORD PAGE  =  Password Management (update)
"""

@views.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
@vault_required
def edit_password(entry_id):
    entry = get_entry(entry_id)
    if entry is None:
        notify('Entry not found.', 'Warning')
        return redirect(url_for('views.home'))

    key = get_vault_key()

    if request.method == 'POST':
        website_name, account_username, account_email, plain_password, note = read_form()

        error = validate_entry(website_name, account_username, account_email, plain_password)
        if error:
            notify(error, 'Warning')
            return render_template('password_form.html', user=current_user, mode='edit',
                                   form=request.form, entry_id=entry_id)

        # re-encrypt the updated password, then replace the old record
        ciphertext = encrypt_password(plain_password, key)
        try:
            run_write(
                "UPDATE credentials SET website_name = %s, account_username = %s, account_email = %s, "
                "encrypted_password = %s, note = %s WHERE id = %s AND user_id = %s",
                (website_name, account_username or None, account_email or None, ciphertext,
                 note or None, entry_id, current_user.id)
            )
            update_checksum()
        except mysql.connector.Error as e:
            notify('The changes could not be saved because of a database error.', 'Critical',
                   detail=f'Edit entry failed: {e}')
            return render_template('password_form.html', user=current_user, mode='edit',
                                   form=request.form, entry_id=entry_id)

        notify('Entry updated!', 'Info')
        return redirect(url_for('views.view_password', entry_id=entry_id))

    # GET: decrypt the saved password so it can be shown in the form and edited
    try:
        current_password = decrypt_password(entry['encrypted_password'], key)
    except ValueError:
        notify('This entry could not be decrypted. It may be corrupted or have been tampered with.',
               'Critical', detail=f'Decryption failed for entry id {entry_id}')
        return redirect(url_for('views.home'))

    form = {
        'website_name': entry['website_name'],
        'account_username': entry['account_username'] or '',
        'account_email': entry['account_email'] or '',
        'password': current_password,
        'note': entry['note'] or '',
    }
    return render_template('password_form.html', user=current_user, mode='edit', form=form, entry_id=entry_id)


"""
DELETE  =  Password Management (delete)
The confirmation question ("Are you sure?") is asked in view_password.html before this runs.
"""
@views.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_password(entry_id):
    try:
        deleted = run_write(
            "DELETE FROM credentials WHERE id = %s AND user_id = %s",
            (entry_id, current_user.id)  # user_id check: only your own entries
        )
        if deleted:
            update_checksum()
            notify('Entry deleted.', 'Info')
        else:
            notify('Entry not found.', 'Warning')
    except mysql.connector.Error as e:
        notify('The entry could not be deleted because of a database error.', 'Critical',
               detail=f'Delete entry failed: {e}')

    return redirect(url_for('views.home'))