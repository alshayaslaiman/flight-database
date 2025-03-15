import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# ==================== Hardcoded FlightAware API Key ==================== #
FLIGHTAWARE_API_KEY = "gy7KekwaegTTb8n0NzHklfDGYSjwNhui"  # Replace this with your real API key

# ==================== Initialize Flask App ==================== #
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flight_database.db'
app.config['SECRET_KEY'] = 'mysecretkey'

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# ==================== USER MODEL ==================== #
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# ==================== FLIGHT MODEL ==================== #
class Flight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flight_number = db.Column(db.String(100), nullable=False)
    departure_date = db.Column(db.String(50), nullable=False)
    arrival_date = db.Column(db.String(50), nullable=False)
    departure_airport = db.Column(db.String(100), nullable=False)
    arrival_airport = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    year = db.Column(db.Integer, nullable=False)  # New: Track flight year

# ==================== CREATE DATABASE TABLES ==================== #
with app.app_context():
    db.create_all()

# ==================== USER AUTHENTICATION ==================== #
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Username already taken. Choose another one.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ==================== DASHBOARD ==================== #
@app.route('/dashboard')
@login_required
def dashboard():
    flights = Flight.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', flights=flights)

# ==================== ADD A FLIGHT ==================== #
@app.route('/add_flight', methods=['GET', 'POST'])
@login_required
def add_flight():
    if request.method == 'POST':
        flight_number = request.form['flight_number']
        departure_date = request.form['departure_date']
        arrival_date = request.form['arrival_date']
        departure_airport = request.form['departure_airport']
        arrival_airport = request.form['arrival_airport']

        new_flight = Flight(
            flight_number=flight_number,
            departure_date=departure_date,
            arrival_date=arrival_date,
            departure_airport=departure_airport,
            arrival_airport=arrival_airport,
            user_id=current_user.id
        )

        db.session.add(new_flight)
        db.session.commit()
        flash('Flight added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_flight.html')

# ==================== TRACK A FLIGHT (FlightAware API) ==================== #
@app.route('/track/<flight_number>')
@login_required
def track_flight(flight_number):
    try:
        url = f"https://aeroapi.flightaware.com/aeroapi/flights/{flight_number}"
        headers = {"x-apikey": FLIGHTAWARE_API_KEY}

        response = requests.get(url, headers=headers)
        data = response.json()

        if "flights" in data and len(data["flights"]) > 0:
            flight_info = data["flights"][0]
            return render_template('track.html', flight=flight_info)
        else:
            return "Flight not found."

    except Exception as e:
        return f"Error fetching flight data: {e}"


@app.route('/delete_flight/<int:flight_id>', methods=['POST'])
@login_required
def delete_flight(flight_id):
    flight = Flight.query.get(flight_id)
    if flight and flight.user_id == current_user.id:
        db.session.delete(flight)
        db.session.commit()
        flash("Flight deleted successfully!", "success")
    else:
        flash("You do not have permission to delete this flight.", "danger")

    return redirect(url_for('dashboard'))


# ==================== RUN FLASK APP ==================== #
if __name__ == '__main__':
    app.run(debug=True)
