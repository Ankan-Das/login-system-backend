from flask import Flask, request, jsonify, session, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_migrate import Migrate

import os

# Create the Flask app instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL','sqlite:///users.db')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY','your_secret_key')
app.config['SESSION_COOKIE_SECURE'] = True      # For HTTPS only
app.config['SESSION_COOKIE_SAMESITE'] = 'None'

# Initialize the extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

print("Migrating ...")
migrate = Migrate(app, db)
print("Migrating Done!")

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "https://login-system-frontend-rho.vercel.app"}})
# CORS(app, supports_credentials=True)
# Define the database model directly in app.py
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"

# Ensure tables are created within the app context
with app.app_context():
    db.create_all()

# Define the routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')
    role = data.get('role')

    if not (name and username and password and confirm_password and role):
        return jsonify({"message": "All fields are required"}), 400

    if password != confirm_password:
        return jsonify({"message": "Passwords do not match"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400

    new_user = User(name=name, username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Registration successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password) and user.role == role:
        session['user_id'] = user.id
        print("inside login", session)
        response = make_response(jsonify({"message": "Login successful"}), 200)

        return response

    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/check_session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        return jsonify({"logged_in": True}), 200
    return jsonify({"logged_in": False}), 401

@app.route('/home', methods=['GET'])
def home():
    print(session)
    if 'user_id' in session:
        return jsonify({"message": "Welcome to the Home Page"})
    return jsonify({"message": "No user is currently logged in"}), 400

@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({"message": "Logout successful"}))
    # Remove session ID cookie or clear the session
    response.set_cookie('session_id', '', expires=0)  # Clears the cookie by setting an expiration in the past
    session.pop('user_id', None)  # Remove user_id from session (optional if you use session)

    return response

@app.route('/test', methods=['GET'])
def test():
    print(session)
    return 'test'


print("All Set !!!")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=10000)