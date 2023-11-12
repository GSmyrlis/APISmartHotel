import sqlite3
import jwt
from functools import wraps
from flask_bcrypt import Bcrypt
from flask import Flask, request, jsonify
from flask_cors import CORS


app = Flask(__name__)
# Apply CORS to the Flask app with the custom options
CORS(app)
bcrypt = Bcrypt(app)

SECRET_KEY = "DiplomaHotelKey"

def connect_db():
    conn = None
    try:
        conn = sqlite3.connect('hotel.db')
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to the database: {e}")
        return None
    
def create_tables():
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS hotel (
                id INTEGER PRIMARY KEY,
                HotelName TEXT,
                HotelAddress TEXT,
                HotelInfo TEXT,
                HotelEmail TEXT,
                HotelWebsite TEXT,
                RestaurantMenuLink TEXT,
                ReceptionTelephone TEXT,
                AboutHotelHtmlContent TEXT
            )'''
        )
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS room (
                id INTEGER PRIMARY KEY,
                RoomNumber INTEGER UNIQUE,
                CleaningServiceActivate INTEGER,
                RateHospitality INTEGER,
                RateComfort INTEGER,
                RateLocation INTEGER,
                RateFacilities INTEGER,
                RateOverall INTEGER
            )'''
        )
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS RestaurantReservation (
             id INTEGER PRIMARY KEY,
             RoomNumber INTEGER NOT NULL,
             RestaurantReservPeopleNumber INTEGER,
             RestaurantReservDateTime TEXT NOT NULL,
             RestaurantReservComment TEXT,
             RequestState INTEGER NOT NULL DEFAULT 1,
             AdminMessage TEXT
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS CleaningServiceReservation (
             id INTEGER PRIMARY KEY,
             RoomNumber INTEGER NOT NULL,
             CleaningServiceReservDateTime TEXT,
             RequestState INTEGER NOT NULL DEFAULT 1,
             AdminMessage TEXT
        )''')
        
        conn.commit()
        
create_tables()

def set_initial_data():
    with connect_db() as conn:
        cursor = conn.cursor()

        # Set initial hotel data if it doesn't exist
        cursor.execute('SELECT * FROM hotel WHERE id = 1')
        hotel_result = cursor.fetchone()
        if not hotel_result:
            initial_hotel_data = {
                "HotelName": "Hotel Kasterini",
                "HotelAddress": "123 Main St",
                "HotelInfo": "This is the Kasterini Hotel, created by GSmyrlis in the old times of the army. This Hotel was created to be the main example we wanna use.",
                "HotelEmail": "info@hotelkasterini.com",
                "HotelWebsite": "https://www.hotelkasterini.com",
                "RestaurantMenuLink": "https://d1csarkz8obe9u.cloudfront.net/posterpreviews/hotel-menu-design-template-20a15f95fc5ddede578ace32a43efc6b_screen.jpg?ts=1637031006",
                "ReceptionTelephone": "00302351047552"
            }
            cursor.execute('INSERT INTO hotel (id, HotelName, HotelAddress, HotelInfo, HotelEmail, HotelWebsite, RestaurantMenuLink, ReceptionTelephone) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           (1, initial_hotel_data["HotelName"], initial_hotel_data["HotelAddress"], initial_hotel_data["HotelInfo"], initial_hotel_data["HotelEmail"], initial_hotel_data["HotelWebsite"], initial_hotel_data["RestaurantMenuLink"], initial_hotel_data["ReceptionTelephone"]))
            conn.commit()

        # Set initial room data if it doesn't exist
        cursor.execute('SELECT * FROM room WHERE id = 1')
        room_result = cursor.fetchone()
        if not room_result:
            initial_room_data = {
                "RoomNumber": 1,
                "CleaningServiceActivate": 1,
                "RateHospitality": 0,
                "RateComfort": 0,
                "RateLocation": 0,
                "RateFacilities": 0,
                "RateOverall": 0
            }
            cursor.execute('REPLACE INTO room (id, RoomNumber, CleaningServiceActivate, RateHospitality, RateComfort, RateLocation, RateFacilities, RateOverall) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           (1, initial_room_data["RoomNumber"], initial_room_data["CleaningServiceActivate"], initial_room_data["RateHospitality"], initial_room_data["RateComfort"], initial_room_data["RateLocation"], initial_room_data["RateFacilities"], initial_room_data["RateOverall"]))
            conn.commit()

        # Set initial RestaurantReservation data if it doesn't exist
        cursor.execute('SELECT * FROM RestaurantReservation WHERE id = 1')
        restaurant_reservation_result = cursor.fetchone()
        if not restaurant_reservation_result:
            initial_restaurant_reservation_data = {
                "RoomNumber": 1,
                "RestaurantReservPeopleNumber": 4,
                "RestaurantReservDateTime": "25/08/2023 21:30:00",
                "RestaurantReservComment": "The table in the middle"
            }
            cursor.execute('INSERT INTO RestaurantReservation (RoomNumber, RestaurantReservPeopleNumber, RestaurantReservDateTime, RestaurantReservComment) VALUES (?, ?, ?, ?)',
                           (initial_restaurant_reservation_data["RoomNumber"], initial_restaurant_reservation_data["RestaurantReservPeopleNumber"], initial_restaurant_reservation_data["RestaurantReservDateTime"], initial_restaurant_reservation_data["RestaurantReservComment"]))
            conn.commit()

        # Set initial CleaningService data if it doesn't exist
        cursor.execute('SELECT * FROM CleaningServiceReservation WHERE id = 1')
        cleaning_service_result = cursor.fetchone()
        if not cleaning_service_result:
            initial_cleaning_service_data = {
                "RoomNumber": 1,
                "CleaningServiceReservDateTime": "25/08/2023 21:30:00"
                }
            cursor.execute('INSERT INTO CleaningServiceReservation (RoomNumber, CleaningServiceReservDateTime) VALUES (?, ?)',
                           (initial_cleaning_service_data["RoomNumber"], initial_cleaning_service_data["CleaningServiceReservDateTime"]))
            conn.commit()

set_initial_data()  # Set initial data for hotel, room, RestaurantReservation, and CleaningService tables if they don't exist

DB_FILE = "hotel.db"

def create_tables():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        role TEXT NOT NULL,
        RoomNumber INTEGER NOT NULL
    )''')
    
    conn.commit()
    conn.close()

create_tables()  # Create the users table if it doesn't exist

# Middleware to validate bearer token
def validate_token(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get("Authorization")
            if token and token.startswith("Bearer "):
                try:
                    decoded_token = jwt.decode(token.split()[1], SECRET_KEY, algorithms=["HS256"])

                    user_role = decoded_token["role"]

                    if roles and user_role not in roles:
                        return jsonify({"message": "Unauthorized role"}), 403

                    return f(decoded_token, *args, **kwargs)
                except jwt.ExpiredSignatureError:
                    return jsonify({"message": "Token has expired"}), 401
                except jwt.InvalidTokenError:
                    return jsonify({"message": "Invalid token"}), 401
            else:
                return jsonify({"message": "Missing or invalid token"}), 401

        return decorated_function
    return decorator



# Protected route accessible with valid token
@app.route('/protected', methods=['GET'])
@validate_token(roles=["user", "admin"])
def protected_route(decoded_token):
    user_id = decoded_token["user_id"]
    role = decoded_token["role"]
    RoomNumber = decoded_token["RoomNumber"]
    return jsonify({"user_id": user_id, "role": role, "RoomNumber": RoomNumber})
    
if __name__ == '__main__':
    app.run()
 
  
  

### --- THE CALLS --- ###
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    RoomNumber = data.get('RoomNumber')

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Check if username already exists
    cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    if result[0] > 0:
        conn.close()
        return jsonify({"message": "Username already exists. Please choose a different username"}), 409

    # Hash and salt the password before storing
    hashed_password = bcrypt.generate_password_hash(password, rounds=12).decode('utf-8')
    cursor.execute('INSERT INTO users (username, hashed_password, role, RoomNumber) VALUES (?, ?, ?, ?)',
                   (username, hashed_password, role, RoomNumber))
    conn.commit()
    conn.close()

    return jsonify({"message": "User registered successfully"}), 201

def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        bearer_token = request.headers.get('Authorization')
        if not bearer_token:
            return jsonify({"error": "No bearer token provided."}), 401

        token = bearer_token.split(' ')[1]
        
        try:
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            print: decoded_token
            if decoded_token.get('role') == 'admin':
                # User is an admin
                return func(*args, **kwargs)
            else:
                # User is not an admin
                return jsonify({"error": "Access denied. Admin access required."}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401

    return decorated_function

@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('SELECT username, role, RoomNumber FROM users')
    users = cursor.fetchall()

    conn.close()

    # Prepare the response
    user_list = []
    for user in users:
        user_list.append({
            'username': user[0],
            'role': user[1],
            'RoomNumber': user[2]
        })

    return jsonify(user_list), 200


# Login route to generate token
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()

        if user_data:
            hashed_password = user_data[2]  # Hashed password stored in the database

            # Compare hashed passwords using bcrypt
            if bcrypt.check_password_hash(hashed_password, password):
                user_id = user_data[0]
                role = user_data[3]
                RoomNumber = user_data[4]
                token = jwt.encode({"user_id": user_id, "role": role, "RoomNumber": RoomNumber}, SECRET_KEY, algorithm="HS256")
                return jsonify({"token": f"Bearer {token}"})

    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/hotel', methods=['POST'])
@admin_required
def set_hotel_data():
    hotel_id = 1  # Assuming we are using one row for the hotel data in the database
    data = request.json
    
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400
    
    with connect_db() as conn:
        cursor = conn.cursor()
        for key, value in data.items():
            if key in data:
                cursor.execute(f"UPDATE hotel SET {key} = ? WHERE id = ?", (value, hotel_id))
        conn.commit()

    return jsonify({"message": "Hotel data updated successfully."}), 201

@app.route('/api/hotel', methods=['GET'])
def get_hotel_data():
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hotel WHERE id = 1")
        result = cursor.fetchone()
        if result:
            data = {
                "HotelName": result[1],
                "HotelAddress": result[2],
                "HotelInfo": result[3],
                "HotelEmail": result[4],
                "HotelWebsite": result[5],
                "RestaurantMenuLink": result[6],
                "ReceptionTelephone": result[7]
            }
            return jsonify(data)
        else:
            return jsonify({"message": "Hotel data not found."}), 404
        
        
@app.route('/api/hotel/rooms', methods=['GET'])
@admin_required
def get_all_room_data():
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM room")
        rooms = cursor.fetchall()
        room_list = []
        for result in rooms:
            data = {
                "RoomNumber": result[1],
                "CleaningServiceActivate": bool(result[2]),
                "RateHospitality": result[3],
                "RateComfort": result[4],
                "RateLocation": result[5],
                "RateFacilities": result[6],
                "RateOverall": result[7]
            }
            room_list.append(data)
        return jsonify(room_list)

@app.route('/api/hotel/rooms', methods=['POST'])
@admin_required
def set_rooms():
    rooms_data = request.get_json()

    inserted_rooms = []

    for room_data in rooms_data:
        room_number = room_data.get('RoomNumber')
        cleaning_service_activate = room_data.get('CleaningServiceActivate')
        rate_hospitality = room_data.get('RateHospitality')
        rate_comfort = room_data.get('RateComfort')
        rate_location = room_data.get('RateLocation')
        rate_facilities = room_data.get('RateFacilities')
        rate_overall = room_data.get('RateOverall')

        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "REPLACE INTO room (RoomNumber, CleaningServiceActivate, RateHospitality, RateComfort, RateLocation, RateFacilities, RateOverall) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (room_number, cleaning_service_activate, rate_hospitality, rate_comfort, rate_location, rate_facilities, rate_overall)
            )
            conn.commit()

        inserted_rooms.append(room_number)

    return jsonify({"message": "Rooms updated successfully", "inserted_rooms": inserted_rooms})

@app.route('/api/hotel/room', methods=['POST'])
@validate_token(roles=["user"])
def post_room(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]

    data = request.get_json()
    CleaningServiceActivate = data.get('CleaningServiceActivate')
    RateHospitality = data.get('RateHospitality')
    RateComfort = data.get('RateComfort')
    RateLocation = data.get('RateLocation')
    RateFacilities = data.get('RateFacilities')
    RateOverall = data.get('RateOverall')

    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('REPLACE INTO room (RoomNumber, CleaningServiceActivate, RateHospitality, RateComfort, RateLocation, RateFacilities, RateOverall) VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (RoomNumber, CleaningServiceActivate, RateHospitality, RateComfort, RateLocation, RateFacilities, RateOverall))
        conn.commit()

    return jsonify({"message": "Room added successfully"}), 201

@app.route('/api/hotel/room', methods=['GET'])
@validate_token(roles=["user"])
def get_room_data(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM room WHERE RoomNumber = ?", (RoomNumber,))
        result = cursor.fetchone()
        if result:
            data = {
                "CleaningServiceActivate": bool(result[2]),
                "RateHospitality": result[3],
                "RateComfort": result[4],
                "RateLocation": result[5],
                "RateFacilities": result[6],
                "RateOverall": result[7]
            }
            return jsonify(data)
        else:
            return jsonify({"message": "Room data not found."}), 404

@app.route('/api/hotel/room/cleaning-activate', methods=['GET'])
@validate_token(roles=["user"])
def get_cleaning_service_activate(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT CleaningServiceActivate FROM room WHERE RoomNumber = ?", (RoomNumber,))
        result = cursor.fetchone()
        if result:
            cleaning_service_activate = bool(result[0])
            return jsonify({"CleaningServiceActivate": cleaning_service_activate})
        else:
            return jsonify({"message": "Room data not found."}), 404

@app.route('/api/hotel/room/cleaning-activate', methods=['POST'])
@validate_token(roles=["user"])
def update_cleaning_service_activate(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    data = request.json
    cleaning_service_activate = data.get('CleaningServiceActivate')

    if cleaning_service_activate is None:
        return jsonify({"error": "Missing required data"}), 400

    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE room SET CleaningServiceActivate = ? WHERE RoomNumber = ?',
                       (cleaning_service_activate, RoomNumber))
        conn.commit()

    return jsonify({"message": "CleaningServiceActivate updated successfully."}), 200


@app.route('/api/hotel/restaurant', methods=['GET'])
@validate_token(roles=["user"])
def get_restaurant_data(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM RestaurantReservation WHERE RoomNumber = ?", (RoomNumber,))
        results = cursor.fetchall()
        if results:
            data_list = []
            for result in results:
                data = {
                "RestaurantReservPeopleNumber": result[2],
                "RestaurantReservComment": result[4],
                "RestaurantReservDateTime": result[3],
                "RequestState": result[5],
                "AdminMessage": result[6]
                }
                data_list.append(data)
            return jsonify(data_list)
        else:
            return jsonify({"message": "Restaurant reservation data not found."}), 404

@app.route('/api/hotel/cleaning', methods=['GET'])
@validate_token(roles=["user"])
def get_cleaning_data(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM CleaningServiceReservation WHERE RoomNumber = ?", (RoomNumber,))
        results = cursor.fetchall()
        if results:
            data_list = []
            for result in results:
                data = {
                "CleaningServiceReservDateTime": result[2],
                "RequestState": result[3],
                "AdminMessage": result[4]
                }
                data_list.append(data)
            return jsonify(data_list)
        else:
            return jsonify({"message": "Cleaning service reservation data not found."}), 404

@app.route('/api/hotel/restaurant', methods=['POST'])
@validate_token(roles=["user"])
def post_restaurant_data(decoded_token):
    data = request.json

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    # Check if the provided datetime has more than 20 approved reservations globally
    existing_reservations = get_existing_reservations(data.get("RestaurantReservDateTime"))
    approved_count = count_approved_reservations(existing_reservations)

    if approved_count >= 20:
        return jsonify({"error": "No more tables available for reservation at this datetime."}), 400

    # Insert the new reservation
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO RestaurantReservation (RoomNumber, RestaurantReservPeopleNumber, RestaurantReservComment, RestaurantReservDateTime) VALUES (?, ?, ?, ?)',
                       (decoded_token["RoomNumber"], data.get("RestaurantReservPeopleNumber"), data.get("RestaurantReservComment"), data.get("RestaurantReservDateTime")))
        conn.commit()

    return jsonify({"message": "Restaurant reservation data posted successfully."}), 201

def get_existing_reservations(RestaurantReservDateTime):
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM RestaurantReservation WHERE RestaurantReservDateTime = ?", (RestaurantReservDateTime,))
        results = cursor.fetchall()
        return results
    
def count_approved_reservations(reservations):
    approved_count = 0
    for reservation in reservations:
        if reservation[5] == "2":
            approved_count += 1
    return approved_count

@app.route('/api/hotel/restaurant', methods=['DELETE'])
@validate_token(roles=["user"])
def delete_restaurant_request(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    data = request.json

    restaurant_reserv_people_number = data.get("RestaurantReservPeopleNumber")
    restaurant_reserv_comment = data.get("RestaurantReservComment")
    restaurant_reserv_datetime = data.get("RestaurantReservDateTime")

    if not restaurant_reserv_people_number or not restaurant_reserv_datetime:
        return jsonify({"error": "Missing required data"}), 400

    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM RestaurantReservation WHERE RoomNumber = ? AND RestaurantReservPeopleNumber = ? AND (RestaurantReservComment = ? OR RestaurantReservComment IS NULL) AND RestaurantReservDateTime = ?",
                       (RoomNumber, restaurant_reserv_people_number, restaurant_reserv_comment, restaurant_reserv_datetime))
        conn.commit()

    return jsonify({"message": "Restaurant reservation request deleted successfully."}), 200

@app.route('/api/hotel/restaurant/<int:request_id>', methods=['DELETE'])
@admin_required
def delete_request_by_id(request_id):
    try:
        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM RestaurantReservation WHERE id = ?", (request_id,))
            conn.commit()

        return jsonify({"message": f"Restaurant request with ID {request_id} deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/hotel/cleaning', methods=['POST'])
@validate_token(roles=["user"])
def post_cleaning_data(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    data = request.json

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO CleaningServiceReservation (RoomNumber, CleaningServiceReservDateTime) VALUES (?, ?)',
                       (RoomNumber, data.get("CleaningServiceReservDateTime")))
        conn.commit()

    return jsonify({"message": "Cleaning service data posted successfully."}), 201

@app.route('/api/hotel/cleaning', methods=['DELETE'])
@validate_token(roles=["user"])
def delete_cleaning_request(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    
    # Get the JSON data from the request body
    json_data = request.get_json()

    if not json_data:
        return jsonify({"error": "Missing JSON data in the request body"}), 400

    # Extract the CleaningServiceReservDateTime from the JSON data
    cleaning_service_reserv_datetime = json_data.get("CleaningServiceReservDateTime")

    if not cleaning_service_reserv_datetime:
        return jsonify({"error": "Missing CleaningServiceReservDateTime in JSON data"}), 400

    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM CleaningServiceReservation WHERE RoomNumber = ? AND CleaningServiceReservDateTime = ?",
                       (RoomNumber, cleaning_service_reserv_datetime))
        conn.commit()

    return jsonify({"message": "Cleaning service request deleted successfully."}), 200

@app.route('/api/hotel/cleaning/<int:request_id>', methods=['DELETE'])
@admin_required
def delete_cleaning_request_by_id(request_id):
    try:
        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM CleaningServiceReservation WHERE id = ?", (request_id,))
            conn.commit()

        return jsonify({"message": f"Cleaning service request with ID {request_id} deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/hotel/rating', methods=['GET'])
@validate_token(roles=["user"])
def get_rating_data(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM room WHERE RoomNumber = ?", (RoomNumber,))
        result = cursor.fetchone()
        print("result is : ", result ) 
        if result:
            data = {
                "RateHospitality": result[3],
                "RateComfort": result[4],
                "RateLocation": result[5],
                "RateFacilities": result[6],
                "RateOverall": result[7]
            }
            return jsonify(data)
        else:
            return jsonify({"message": "Hotel data not found."}), 404   

@app.route('/api/hotel/rating', methods=['POST'])
@validate_token(roles=["user"])
def post_rating_data(decoded_token):
    RoomNumber = decoded_token["RoomNumber"]
    data = request.json
    
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400
    
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE room SET RateComfort = ?, RateFacilities = ?, RateHospitality = ?, RateLocation = ?, RateOverall = ?  WHERE RoomNumber = ?',
                       (data.get("RateComfort"), data.get("RateFacilities"), data.get("RateHospitality"), data.get("RateLocation"), data.get("RateOverall"), RoomNumber))
        conn.commit()

    return jsonify({"message": "Hotel rating posted successfully."}), 201

@app.route('/api/hotel/restaurants', methods=['GET'])
@admin_required
def get_all_restaurant_reservations():
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM RestaurantReservation")
        results = cursor.fetchall()
        reservation_list = []
        for result in results:
            reservation = {
                "id": result[0],
                "RoomNumber": result[1],
                "RestaurantReservPeopleNumber": result[2],
                "RestaurantReservComment": result[4],
                "RestaurantReservDateTime": result[3],
                "RequestState": result[5],
                "AdminMessage": result[6]
            }
            reservation_list.append(reservation)
        return jsonify(reservation_list)

@app.route('/api/hotel/cleanings', methods=['GET'])
@admin_required
def get_all_cleaning_service_reservations():
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM CleaningServiceReservation")
        results = cursor.fetchall()
        reservation_list = []
        for result in results:
            reservation = {
                "id": result[0],
                "RoomNumber": result[1],
                "CleaningServiceReservDateTime": result[2],
                "RequestState": result[3],
                "AdminMessage": result[4]
            }
            reservation_list.append(reservation)
        return jsonify(reservation_list)

@app.route('/api/hotel/restaurant/<int:reservation_id>', methods=['POST'])
@admin_required
def update_restaurant_reservation(reservation_id):
    data = request.json
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE RestaurantReservation SET RequestState = ?, AdminMessage = ? WHERE id = ?',
                       (data.get("RequestState"), data.get("AdminMessage"), reservation_id))
        conn.commit()
    return jsonify({"message": "Restaurant reservation updated successfully."})

@app.route('/api/hotel/cleaning/<int:reservation_id>', methods=['POST'])
@admin_required
def update_cleaning_service_reservation(reservation_id):
    data = request.json
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE CleaningServiceReservation SET RequestState = ?, AdminMessage = ? WHERE id = ?',
                       (data.get("RequestState"), data.get("AdminMessage"), reservation_id))
        conn.commit()
    return jsonify({"message": "Cleaning service reservation updated successfully."})

@app.route('/api/hotel/about', methods=['GET'])
def get_about_hotel():
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT AboutHotelHtmlContent FROM hotel WHERE id = 1")
        result = cursor.fetchone()
        if result:
            return jsonify({"AboutHotelHtmlContent": result[0]})
        else:
            return jsonify({"message": "About Hotel data not found."}), 404
        
import base64

@app.route('/api/rates', methods=['GET'])
@admin_required
def get_all_rates():
    try:
        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT RateHospitality, RateComfort, RateLocation, RateFacilities, RateOverall, RoomNumber FROM room')
            rates = cursor.fetchall()

            if rates:
                # Convert the result to a list of dictionaries
                rate_list = []
                for rate in rates:
                    rate_dict = {
                        'Hospitality': rate[0],
                        'Comfort': rate[1],
                        'Location': rate[2],
                        'Facilities': rate[3],
                        'Overall': rate[4],
                        'RoomNumber': rate[5]
                    }
                    rate_list.append(rate_dict)

                return jsonify(rate_list)
            else:
                return jsonify({'message': 'No rates found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hotel/about', methods=['POST'])
@admin_required
def update_about_hotel():
    data = request.json
    about_hotel_base64 = data.get("AboutHotelHtmlContent")

    if not about_hotel_base64:
        return jsonify({"error": "Missing required data"}), 400

    about_hotel_html_content = about_hotel_base64

    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE hotel SET AboutHotelHtmlContent = ? WHERE id = 1',
                       (about_hotel_html_content,))
        conn.commit()

    return jsonify({"message": "About Hotel data updated successfully."}), 200



if __name__ == '__main__':
    app.run()