# test_sqli.py — SQL injection: tainted input flows to cursor.execute
import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    user_input = input("Enter username: ")          # SOURCE
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)                            # SINK — tainted!
    return cursor.fetchall()
