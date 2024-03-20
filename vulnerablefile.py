import sqlite3

# Vulnerable function that executes an SQL query
def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

# Example usage
username = input("Enter username: ")
password = input("Enter password: ")
result = login(username, password)
if result:
    print("Login successful")
else:
    print("Login failed")
