import mysql.connector

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Cici123456789',
    'database': 'password_manager'
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)