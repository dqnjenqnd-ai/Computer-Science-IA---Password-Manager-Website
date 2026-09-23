"""
One place that handles every message the user sees AND every log entry:
    * level 'Info' --> normal feedback
        (e.g. "Entry added!")
    * level 'Warning' --> the user did something invalid
        (e.g. "Passwords don't match")
    * level 'Critical' --> something is wrong with the system / the data
        (e.g. failed integrity check, database error)

Every message is (1) shown to the user as a coloured alert and
(2) recorded in the local log file "error.log" and in the system_logs table.
"""

import logging
from flask import flash
from .db import get_db_connection

LEVELS = ('Info', 'Warning', 'Critical') # same values as the ENUM in the system_logs table

# the local log file
# created next to the file you run (error.log).
logging.basicConfig(
    filename='error.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

_PYTHON_LEVELS = {
    'Info': logging.INFO,
    'Warning': logging.WARNING,
    'Critical': logging.CRITICAL,
}


def log_event(level, message):
    # Write one event to the log file AND to the system_logs table.
    if level not in LEVELS:
        level = 'Info'

    logging.log(_PYTHON_LEVELS[level], message)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO system_logs (error_type, error_message) VALUES (%s, %s)",
            (level, message)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        # Logging must never crash the app. If the database is down, the file log still has it.
        logging.critical(f'Could not write to system_logs table: {e}')


def notify(message, level='Info', detail=None):
    """Show 'message' to the user and log it.

    message: short, friendly text the user sees
    level: 'Info', 'Warning' or 'Critical'
    detail: optional technical text that goes into the log only, so the user never sees raw error text.
            (e.g. the database error)
    NEVER put a password or a decrypted value in `message` or `detail`.
    """
    if level not in LEVELS:
        level = 'Info'
    flash(message, category=level)          # base.html turns the category into a coloured alert
    log_event(level, detail or message)