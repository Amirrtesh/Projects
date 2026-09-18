from flask import Flask, render_template, request, session, redirect
import sqlite3

app = Flask(__name__)

app.secret_key = "local-development-secret-key"

DATABASE = "users.db"


# ============================================================
# DATABASE
# ============================================================

def init_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# LOGIN PAGE
# ============================================================

@app.route("/", methods=["GET", "POST"])
def login():

    message = ""

    if request.method == "POST":

        email = request.form.get("email", "")
        password = request.form.get("password", "")

        # ----------------------------------------------------
        # IMPORTANT:
        # This is only a demonstration application.
        # Password is NOT stored.
        # ----------------------------------------------------

        if email == "test@example.com" and password == "Test@123":

            session["user"] = email

            return redirect("/dashboard")

        message = "Invalid email or password."

    return render_template(
        "login.html",
        message=message
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:

        return redirect("/")

    return render_template(
        "dashboard.html",
        email=session["user"]
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )