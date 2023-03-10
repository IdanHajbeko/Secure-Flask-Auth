import re
import bcrypt
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g
import datetime

app = Flask(__name__)

# Set up database connection
DATABASE = "users.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


# Initialize users table if it doesn't exist
with app.app_context():
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT, created_at DATETIME)"""
    )
    db.commit()

# Set up dictionary to keep track of failed login attempts
failed_attempts = {}


# Function to create a new user account
@app.route("/create_account", methods=["GET", "POST"])
def create_account():
    db = get_db()
    cursor = db.cursor()
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not re.match("^[a-zA-Z0-9_]{4,}$", username):
            return render_template(
                "create_account.html",
                error="Username must be at least 4 characters long and contain only letters, numbers, and underscores.",
            )
        if not re.match("^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$", password):
            return render_template(
                "create_account.html",
                error="Password must be at least 8 characters long and contain at least one letter and one number.",
            )
        # Generate a unique salt for the user
        salt = bcrypt.gensalt()
        # Hash the password using bcrypt and the salt
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        # Write the username, hashed password, and salt to the database using a parameterized query
        try:
            cursor.execute(
                "INSERT INTO users (username, password, salt, created_at) VALUES (?, ?, ?, ?)",
                (username, hashed_password, salt, datetime.datetime.now()),
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            db.rollback()
            return render_template(
                "create_account.html",
                error="Username already exists. Please choose a different username.",
            )
    else:
        return render_template("create_account.html")


# Function to login to an existing user account
@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    cursor = db.cursor()
    if request.method == "POST":
        username = request.form.get("username", "") # prevents server error
        password = request.form.get("password", "")
        # Check if user has exceeded maximum number of login attempts
        if username in failed_attempts and failed_attempts[username]["attempts"] >= 3:
            return render_template(
                "login.html",
                error="Maximum number of login attempts exceeded. Please try again later.",
            )
        # Retrieve the hashed password and salt from the database using a parameterized query
        cursor.execute("SELECT password, salt FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        if not row:
            # Increment failed login attempts for the user
            if username in failed_attempts:
                failed_attempts[username]["attempts"] += 1
            else:
                failed_attempts[username] = {
                    "attempts": 1,
                    "timestamp": datetime.datetime.now(),
                }
            return render_template("login.html", error="Invalid username or password.")
        hashed_password, salt = row
        # Hash the entered password using bcrypt and the stored salt
        entered_password = bcrypt.hashpw(password.encode(), salt)
        # Check if the hashed entered password matches the stored hashed password
        if hashed_password == entered_password:
            # Reset failed login attempts for the user
            if username in failed_attempts:
                del failed_attempts[username]
            return render_template("welcome.html", username=username)
        else:
            # Increment failed login attempts for the user
            if username in failed_attempts:
                failed_attempts[username]["attempts"] += 1
            else:
                failed_attempts[username] = {
                    "attempts": 1,
                    "timestamp": datetime.datetime.now(),
                }
            attempts_left = 3 - failed_attempts[username]["attempts"]
            return render_template(
                "login.html",
                error="Invalid username or password. You have {} attempts left.".format(
                    attempts_left
                ),
            )
    else:
        return render_template("login.html")


# Main program loop
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/logout")
def logout():
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
