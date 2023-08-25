import os
import string
import random

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash


# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///users.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    return redirect("/generate")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Please provide a username.", "alert")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Please provide a secure password.", "alert")
            return render_template("login.html")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            flash("Invalid username and/or password.", "alert")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to generate password
        return redirect("/generate")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()

    # Redirect user to main page
    return redirect("/generate")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Please provide a username.", "alert")
            return render_template("register.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Please provide a secure password.", "alert")
            return render_template("register.html")

        # Ensure confirmed password was submitted
        elif not request.form.get("confirmation"):
            flash("Please confirm your password.", "alert")
            return render_template("register.html")

        # Ensure both passwords match
        elif request.form.get("confirmation") != request.form.get("password"):
            flash("Passwords don't match.", "alert")
            return render_template("register.html")

        # check if username already exists
        username = request.form.get("username")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        hashedpassword = generate_password_hash(request.form.get("password"))

        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)",
                username,
                hashedpassword,
            )

            # log user in
            rows_ls = db.execute("SELECT id FROM users WHERE username = ?", username)
            rows = rows_ls[0]["id"]

            session["user_id"] = rows
            return redirect("/generate")
        except:
            flash("Username is already taken.", "alert")
            return render_template("register.html")


@app.route("/generate", methods=["GET", "POST"])
def generate():
    if request.method == "GET":
        # default password contains every character UI check the checkboxes
        lowercase_checked = "checked"
        numbers_checked = "checked"
        symbols_checked = "checked"
        uppercase_checked = "checked"
        len = 12

        # password letters: abc+ABC+123+!"§
        letters = (
            string.digits + string.ascii_uppercase + string.ascii_lowercase + "!@#$%^?*"
        )

        password = "".join(random.choice(letters) for i in range(len))

        # Safety indication
        weak_color = "#D3212C"
        medium_color = "#FF980E"
        strong_color = "#ccc"
        indication_text = "Your password is medium"

        return render_template(
            "generate.html",
            password=password,
            len=len,
            symbols=symbols_checked,
            numbers=numbers_checked,
            uppercase=uppercase_checked,
            lowercase=lowercase_checked,
            weak=weak_color,
            medium=medium_color,
            strong=strong_color,
            indication_text=indication_text,
        )

    letters = ""
    len = int(request.form.get("slidervalue"))

    # get checkboxes
    numbers = request.form.get("numbers")
    symbols = request.form.get("symbols")
    uppercase = request.form.get("uppercase")
    lowercase = request.form.get("lowercase")

    # checkboxes default
    numbers_checked = "none"
    symbols_checked = "none"
    uppercase_checked = "none"
    lowercase_checked = "none"

    # check if checkbox is checked
    if numbers == "on":
        letters = letters + string.digits
        numbers_checked = "checked"

    if symbols == "on":
        letters = letters + "!@#$%^?*"
        symbols_checked = "checked"

    if uppercase == "on":
        letters = letters + string.ascii_uppercase
        uppercase_checked = "checked"

    if lowercase == "on":
        letters = letters + string.ascii_lowercase
        lowercase_checked = "checked"

    # Error if no checkbox is checked
    if not numbers and not symbols and not uppercase and not lowercase:
        flash("Please at least select one checkbox!", "alert")
        return render_template("generate.html")

    # Create unique password
    password = "".join(random.choice(letters) for i in range(len))

    # Safety indication
    weak_color = "#ccc"
    medium_color = "#ccc"
    strong_color = "#ccc"
    indication_text = ""

    if len < 10:
        weak_color = "#D3212C"
        medium_color = "#ccc"
        strong_color = "#ccc"
        indication_text = "Your password is too weak"
    elif len > 9 and len < 21:
        weak_color = "#D3212C"
        medium_color = "#FF980E"
        strong_color = "#ccc"
        indication_text = "Your password is medium"
    elif len > 20 and len < 50:
        weak_color = "#D3212C"
        medium_color = "#FF980E"
        strong_color = "#069C56"
        indication_text = "Your password is strong"
    elif len == 50:
        weak_color = "#069C56"
        medium_color = "#069C56"
        strong_color = "#069C56"
        indication_text = "Your password is super strong"

    return render_template(
        "generate.html",
        password=password,
        len=len,
        symbols=symbols_checked,
        numbers=numbers_checked,
        uppercase=uppercase_checked,
        lowercase=lowercase_checked,
        weak=weak_color,
        medium=medium_color,
        strong=strong_color,
        indication_text=indication_text,
    )
