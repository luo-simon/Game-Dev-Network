from cs50 import SQL
from flask import Flask, redirect, render_template, request, session, flash
from flask_session import Session
from tempfile import mkdtemp

from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///game_dev.db")


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "GET":
        data = db.execute("SELECT username, email, role, description FROM users WHERE id=:id", id=session["user_id"])[0]
        username = data["username"]
        email = data["email"]
        role = data["role"]
        desc = data["description"]
        return render_template("profile.html", username=username, email=email, role=role, description=desc)
    else:
        new_role = request.form.get("role")
        new_desc = request.form.get("description")
        db.execute("UPDATE users SET role=:role, description=:desc WHERE id=:id", 
                   role=new_role, 
                   desc=new_desc, 
                   id=session["user_id"])
        print(new_role, new_desc)

        flash("Profile updated!")
        return redirect("/")


@app.route("/user/<username>", methods=["GET", "POST"])
@login_required
def user(username):

    if request.method == "GET":
        user = db.execute("SELECT id, email, role, description from users WHERE username=:username",
                        username=username)[0]

        posts = db.execute("SELECT title, role, text, timestamp FROM posts WHERE user_id=:id LIMIT 5",
                        id=user["id"])

        id = user["id"]
        email = user["email"]
        role = user["role"]
        description = user["description"]

        return render_template("user.html", email=email, username=username, role=role, description=description, posts=posts, id=id)

    else:
        id = request.form.get("id")

        db.execute("INSERT INTO contacts (user_id, contact_id) VALUES (:user_id, :contact_id)",
                   user_id=session["user_id"], contact_id=id)

        flash("User added")
        return redirect("/contacts")


@app.route("/contacts")
@login_required
def contacts():
    contacts = db.execute("SELECT username, role, email FROM users WHERE id IN (SELECT contact_id FROM contacts WHERE user_id=:user_id)",
                          user_id=session["user_id"])

    return render_template("contacts.html", contacts=contacts)


@app.route("/add_post", methods=["GET", "POST"])
@login_required
def add_post():

    if request.method == "GET":
        return render_template("add_post.html")
    
    else:
        title = request.form.get("title")
        role = request.form.get("role")
        text = request.form.get("text")

        db.execute("INSERT INTO posts (user_id, title, role, text) VALUES (:user_id, :title, :role, :text)",
                   user_id=session["user_id"],
                   title=title,
                   role=role,
                   text=text)

        flash("Post created")
        return redirect("/your_posts")

@app.route("/your_posts")
@login_required
def your_posts():
    posts = db.execute(
        "SELECT title, posts.role, text, username, timestamp FROM posts " +
        "JOIN users ON posts.user_id=users.id WHERE user_id=:user_id ORDER BY timestamp DESC",
        user_id=session["user_id"]
    )

    return render_template("posts.html", title="Your posts", posts=posts)


@app.route("/all_posts")
@login_required
def all_posts():
    posts = db.execute(
        "SELECT title, posts.role, text, username, timestamp FROM posts " +
        "JOIN users ON posts.user_id=users.id ORDER BY timestamp DESC")
        
    return render_template("posts.html", title="All posts", posts=posts)


@app.route("/developers")
@login_required
def developers():
    users = db.execute("SELECT username, role, email FROM users ORDER BY role, username")
    return render_template("developers.html", users=users)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        flash("Logged in")
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    flash("Logged out")
    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("register.html")

    # User reached route via POST (as by submitting a form)
    else:

        # Ensure username was submitted:
        if not request.form.get("username"):
            return apology("Must provide username", 403)

        # Ensure password was submitted:
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Must provide password", 403)

        # Ensure two passwords are the same:
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Passwords must match", 403)

        # Ensure user has selected a role
        elif not request.form.get("role"):
            return apology("Must select role", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username does not already exist
        if len(rows) > 0:
            return apology("Username already exists")

        # Insert new user into "users" with the hashed password
        db.execute("INSERT INTO users (email, username, hash, role) VALUES (:email, :username, :hash, :role)",
                   email=request.form.get("email"),
                   username=request.form.get("username"),
                   hash=generate_password_hash(request.form.get("password")),
                   role=request.form.get("role"))

        flash("Registered!")
        # Redirect user to home page
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
