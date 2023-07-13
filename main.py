from flask import Flask, render_template, request, jsonify, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'xyz'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Flight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flight_number = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(20), nullable = False)
    destination =  db.Column(db.String(20), nullable = False)
    date = db.Column(db.Date(), nullable = False )
    available_seats = db.Column(db.Integer, nullable=False)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    flight_id = db.Column(db.Integer, db.ForeignKey('flight.id'), nullable=False)
    booked_at = db.Column(db.DateTime, nullable=False)

with app.app_context():
    db.create_all()
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        # if a user is found, we want to redirect back to signup page so user can try again
        if user:
            flash('Username already exists')
            return redirect('/signup')

        new_user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect('/login') # if the user doesn't exist or password is wrong, reload the page

        # if the above check passes, then we know the user has the right credentials
        login_user(user)
        return redirect('/')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/search-flights', methods=['GET', 'POST'])
@login_required
def search_flights():
    flights = []
    if request.method == 'POST':
        location = request.form.get('location')
        destination = request.form.get('destination')
        date = request.form.get('date')
        
        flights = Flight.query.filter_by(location=location, 
                                          destination = destination, 
                                          date=date).all()
    return render_template('search_flights.html', flights=flights)


@app.route('/book-flight/<int:flight_id>', methods=['GET', 'POST'])
@login_required
def book_flight(flight_id):
    flight = Flight.query.get_or_404(flight_id)

    if request.method == 'POST':
        # Ensure there are seats available
        if flight.available_seats < 1:
            flash('No seats available for this flight', 'danger')
        else:
            # Reduce the number of available seats
            flight.available_seats -= 1
            booking = Booking(user_id=current_user.id, flight_id=flight_id, booked_at=datetime.utcnow())
            db.session.add(booking)
            db.session.commit()
            flash('Flight booked successfully', 'success')
            return redirect(url_for('my_bookings'))

    return render_template('book_flight.html', flight=flight)



@app.route('/my-bookings')
@login_required
def my_bookings():
    bookings = Booking.query.filter_by(user_id=current_user.id).all()
    return render_template('my_bookings.html', bookings=bookings)



@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return "Access denied", 403

    if request.method == 'POST':
        if 'flight_number' in request.form:  # This means the add flight form was submitted
            flight_number = request.form['flight_number']
            location = request.form['location']
            destination = request.form['destination']
            date = datetime.strptime(request.form['date'], '%Y-%m-%d')
            available_seats = int(request.form['available_seats'])

            new_flight = Flight(flight_number=flight_number, location=location, destination=destination, date=date, available_seats=available_seats)
            db.session.add(new_flight)
            db.session.commit()
            flash('Flight added successfully', 'success')

        elif 'flight_id' in request.form:  # This means the remove flight form was submitted
            flight_id = int(request.form['flight_id'])
            flight = Flight.query.get(flight_id)
            if flight:
                db.session.delete(flight)
                db.session.commit()
                flash('Flight removed successfully', 'success')
            else:
                flash('Flight not found', 'danger')
    bookings = Booking.query.all()
    return render_template('admin.html', bookings=bookings)


@app.route('/create-admin', methods=['GET', 'POST'])
def create_admin():
    # if not current_user.is_admin:
    #     return "Access denied", 403

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(username=username, email=email, password=password, is_admin=True)
        db.session.add(new_user)
        db.session.commit()
        flash('Admin user created successfully', 'success')
        return redirect(url_for('home'))

    return render_template('create_admin.html')

@app.route('/clear-database', methods=['GET'])
def clear_database():
    # Delete all tables
    db.reflect()
    db.drop_all()

    return 'Database cleared'



@app.route('/view-flights', methods=['GET'])
@login_required
def view_flights():
    flights = Flight.query.all()
    return render_template('view_flights.html', flights=flights)



if __name__ == "__main__":
    app.run(debug=True)
