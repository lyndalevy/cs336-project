# test_sanitized.py — Parameterized query: taint sanitized before sink
import sqlite3

def get_user():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    user_input = input("Enter username: ")   # SOURCE
    parameterize(user_input)                 # SANITIZER — removes taint from user_input
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (user_input,))     # user_input is now clean: no warning
    return cursor.fetchall()
