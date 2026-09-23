from flask_login import UserMixin
from .db import get_db_connection


class User(UserMixin):
    def __init__(self, id, email, first_name, master_password_hash, account_status):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.master_password_hash = master_password_hash
        self.account_status = account_status

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            return User(row['id'], row['email'], row['first_name'], row['master_password_hash'], row['account_status'])
        return None

    @staticmethod
    def get_by_email(email):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            return User(row['id'], row['email'], row['first_name'], row['master_password_hash'], row['account_status'])
        return None