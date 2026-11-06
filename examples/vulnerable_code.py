import os
import sqlite3

def run_command(user_input):
    os.system("ping " + user_input)

def calculate_math(expression):
    result = eval(expression)
    return result

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()