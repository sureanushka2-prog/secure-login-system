from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyotp
import qrcode
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ------------------ DATABASE ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    return redirect(url_for('login'))

# -------- REGISTER --------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation
        if len(username) < 3 or len(password) < 5:
            return "Invalid input!"

        # Hash password
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        # Generate 2FA secret
        secret = pyotp.random_base32()

        new_user = User(username=username, password=hashed_pw, otp_secret=secret)
        db.session.add(new_user)
        db.session.commit()

        # Generate QR code for Google Authenticator
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureApp")
        img = qrcode.make(uri)
        img.save(f"static/{username}_qr.png")

        return f"Registered! Scan QR in Google Authenticator.<br><img src='/static/{username}_qr.png'>"

    return render_template('register.html')

# -------- LOGIN --------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['temp_user'] = user.username
            return redirect(url_for('verify_2fa'))
        else:
            return "Login Failed!"

    return render_template('login.html')

# -------- 2FA VERIFY --------
@app.route('/verify', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        user = User.query.filter_by(username=session['temp_user']).first()

        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(otp):
            session.pop('temp_user', None)
            session['user'] = user.username
            return redirect(url_for('dashboard'))
        else:
            return "Invalid OTP!"

    return render_template('verify_2fa.html')

# -------- DASHBOARD --------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

# -------- LOGOUT --------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ------------------ RUN ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
