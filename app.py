from flask import Flask,redirect,render_template, jsonify, render_template_string, Response, url_for
from markupsafe import escape
from flask import request
from flask import Flask
from flask import jsonify
from flask import request, session
import base64
from werkzeug.utils import secure_filename
import os
from bson import ObjectId
from datetime import datetime
from google.oauth2 import id_token as tokenq
from google.auth.transport import requests as google_requests
from datetime import datetime
from passlib.hash import bcrypt_sha256
import logging
import secrets
import hashlib

from ultralytics import YOLO
from ultralytics.solutions import object_counter
import cv2
from pymongo import MongoClient
import datetime
import calendar
from shapely.geometry import Point, Polygon
from flask_mail import Mail, Message




from passlib.hash import argon2
from argon2 import PasswordHasher

from pymongo import MongoClient 
from flask_pymongo import PyMongo

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

import google.auth.transport.requests
import google.oauth2.id_token
import locale
locale.setlocale(locale.LC_TIME, 'id_ID.UTF-8')





app = Flask(__name__) # Instantiate Flask
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'syarifm180@gmail.com'
app.config['MAIL_PASSWORD'] = "rnmhrutjsjkhombm"
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


# Import Firebase Admin SDK
import firebase_admin
from firebase_admin import auth, credentials

# Path to your Firebase service account key JSON file
cred = credentials.Certificate("capstone-2d2d4-firebase-adminsdk-a6h40-738162712e.json")
firebase_admin.initialize_app(cred)


# Set up MongoDB connection and collection 
client = MongoClient('mongodb://localhost:27017/') 
# Create database named demo if they don't exist already 
db = client['counting_pengunjung'] 
# Create collection named data if it doesn't exist already 
collection = db['user'] 
collection1 = db['files']
collection2 = db['deteksi']

# Initialize the YOLO model
model = YOLO("gender.pt")

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

# Pastikan direktori untuk menyimpan file ada
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def generate_reset_token(email):
    token = secrets.token_urlsafe(16)
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    collection.update_one({"email": email}, {"$set": {"reset_token": hashed_token}})
    return token

def verify_reset_token(token):
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    # This function should retrieve the email associated with the hashed_token
    # For simplicity, we're assuming a mapping of token to email exists.
    # In a real implementation, you would store and retrieve this mapping securely.
    user = collection.find_one({"reset_token": hashed_token})
    if user:
        return user["email"]
    return None



@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required'}), 400

    user = collection.find_one({"email": email})

    if not user:
        return jsonify({'message': 'Email not found'}), 404

    try:
        # Generate password reset link using Firebase Authentication
        reset_token = generate_reset_token(email)
        
        msg = Message()
        msg.subject = "Reset Your Password"
        msg.recipients = [email]
        msg.sender = "syarifm180@gmail.com"
        msg.body = f"Click the following link to reset your password: " \
                   f"https://ethical-coyote-presently.ngrok-free.app/reset_password_form?token={reset_token}"

        # Send email
        mail.send(msg)

        return jsonify({'message': 'Password reset link sent to your email'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/reset_password_form', methods=['GET'])
def reset_password_form():
    token = request.args.get('token')
    if not token:
        return "Invalid token", 400
    return render_template('reset_password.html', token=token)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    token = request.form.get('token')
    new_password = request.form.get('new_password')

    if not token or not new_password:
        return jsonify({'message': 'Token and new password are required'}), 400

    email = verify_reset_token(token)
    if not email:
        return jsonify({'message': 'Invalid or expired token'}), 400

    hashed_password = argon2.hash(new_password)
    collection.update_one({"email": email}, {"$set": {"password": hashed_password, "reset_token": None}})

    return jsonify({'message': 'Password reset successfully'}), 200


@app.route('/save-detection', methods=['POST'])
def save_detection():      
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Log the received data
    print(f"Received data: {data}")

    lokasi = data.get('lokasi')
    timestamp = data.get('timestamp')
    counts = data.get('counts')

    

    if not timestamp or not counts:
        return jsonify({"error": "Invalid data format"}), 400

    # Extract the date from the timestamp
    try:
        date = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f').date()
        day_name = date.strftime('%A')
    except ValueError as e:
        return jsonify({"error": f"Timestamp format error: {str(e)}"}), 400

    # Upsert the data into MongoDB (update if the date exists, otherwise insert)
    collection2.update_one(
        {'date': str(date), 'day': day_name, 'lokasi': lokasi},
        {'$inc': {f'counts.{key}': value for key, value in counts.items()},
         '$setOnInsert': {'date': str(date), 'day': day_name, 'lokasi': lokasi}},
        upsert=True
    )

    return jsonify({"message": "Detection results saved successfully"}), 200

@app.route('/get-detections', methods=['GET'])
def get_detections():
    detections = list(collection.find({}, {'_id': 0}))  # Exclude the '_id' field
    return jsonify(detections), 200


#jwt
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    user = collection.find_one({"_id": ObjectId(identity)})
    if user:
        user['id'] = str(user['_id'])  # Convert ObjectId to string
        del user['_id']  # Remove the original ObjectId
    return user

@app.route("/user", methods=['GET', 'POST', 'PUT', 'DELETE'])
@jwt_required()
def user():
    if request.method == 'POST':
        dataDict = request.get_json()  # Mengambil data JSON dari request
        email = dataDict.get("email")
        name = dataDict.get("name")
        password = dataDict.get("password")
        
        # Hash password menggunakan Argon2
        hashed_password = argon2.hash(password)
        
        # Membuat objek user baru
        new_user = {
            "email": email,
            "name": name,
            "password": hashed_password,
        }
        
        # Insert data ke MongoDB
        collection.insert_one(new_user)
        
        return jsonify({
            "message": "Successfull",
            "data": f"email: {email}, name : {name}"
        }), 200  
        
    elif request.method == 'PUT':
        dataDict = request.get_json()  # Mengambil data JSON dari request
        user_id = dataDict.get("id")
        email = dataDict.get("email")
        name = dataDict.get("name")
        password_update = dataDict.get("password")
        
        if not user_id:
            return jsonify({"message": "ID required"}), 400
        
        # Hash password baru jika ada
        hashed_password_update = argon2.hash(password_update) if password_update else None
        
        # Update data di MongoDB
        update_data = {}
        if email:
            update_data["email"] = email
        if name:
            update_data["name"] = name
        if hashed_password_update:
            update_data["password"] = hashed_password_update
        
        result = collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            return jsonify({"message": "User not found"}), 404
        
        return jsonify({"message": "Successfull!"}), 200
        
    elif request.method == 'DELETE':
        dataDict = request.get_json()  # Mengambil data JSON dari request
        user_id = dataDict.get("id")
        
        if not user_id:
            return jsonify({"message": "ID required"}), 400
        
        result = collection.delete_one({"_id": ObjectId(user_id)})
        
        if result.deleted_count == 0:
            return jsonify({"message": "User not found"}), 404
        
        return jsonify({"message": "Successfull!"}), 200
        
    else:  # GET
        users = []
        for user in collection.find():
            users.append({
                "id": str(user["_id"]),
                "email": user["email"],
                "name": user["name"],
            })
        return jsonify(users), 200
        

# Method POST 
@app.post('/signup')
def signup():
    dataDict = request.get_json()  # Mendapatkan data JSON dari request
    name = dataDict.get("name")
    email = dataDict.get("email")
    password = dataDict.get("password")
    
    
    # Memeriksa apakah email terisi
    
    if not email:
        return {
            "message": "Email harus diisi"
        }, 400
    
    # Memeriksa apakah email sudah ada di database
    if collection.find_one({"email": email}):
        return {
            "message": "Email sudah terdaftar"
        }, 400
    
    # Menghash password menggunakan Argon2
    hashed_password = argon2.hash(password)
    verifikasi_token = secrets.token_urlsafe(32)
    
    # Membuat objek User dengan menggunakan properti yang sesuai
    new_user = {
        "email": email,
        "name": name,
        "password": hashed_password,
        "isVerified" : False,
        "verification_token": verifikasi_token
    }

    # Insert data into MongoDB
    collection.insert_one(new_user)

    konfirmasi_url= url_for('confirm_email',token=verifikasi_token,_external=True)
   
    msg = Message()
    msg.subject = "Konfirmasi Password"
    msg.recipients = [email]
    msg.sender = "syarifm180@gmail.com"
    msg.body = f"Klik tautan berikut untuk mengkonfirmasi email Anda: {konfirmasi_url}"

    # Send email
    mail.send(msg)
    
    return {
        "message": "Successfully registered"
    }, 201

@app.route('/confirm_email/<token>')
def confirm_email(token):
    user = collection.find_one({"verification_token": token})
    if user:
        collection.update_one({"verification_token": token}, {"$set": {"isVerified": True}})
        return "Email Anda telah terverifikasi."
    return "Token tidak valid atau sudah kadaluarsa.", 400  
        
    

@app.route("/sigin", methods=["POST"])
def signin():
    # Mendapatkan Authorization header
    base64Str = request.headers.get('Authorization')
    base64Str = base64Str[6:]  # Hapus "Basic" string
    
    # Base64 Decode
    base64Bytes = base64Str.encode('ascii')
    messageBytes = base64.b64decode(base64Bytes)
    pair = messageBytes.decode('ascii')
    
    email, password = pair.split(":")
    
    # Query user dari MongoDB
    user_data = collection.find_one({"email": email})
    
    if not user_data or not argon2.verify(password, user_data['password']):
        return {
            "message": "wrong password or email!"
        }, 400
    
    # Menghasilkan JWT token
    access_token = create_access_token(identity=str(user_data['_id']))
    
    # Mengembalikan respons
    return {
        "token_access": access_token,
        "user_id": str(user_data['_id']),
        "name": user_data['name'],
        "email": user_data['email']
    }, 200
    
@app.post("/login")
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return {
            "message": "Email dan kata sandi diperlukan!"
        }, 400
    
    # Mencari pengguna berdasarkan email
    user = collection.find_one({"email": email})
    
    if not user:
        return jsonify({"message": "Email atau kata sandi salah!"}), 400
    
    try:
        if not argon2.verify(password, user['password']):
            return jsonify({"message": "Email atau kata sandi salah!"}), 400
    except:
        return jsonify({"message": "Email atau kata sandi salah!"}), 400
    
    if not user.get("isVerified"):
        return jsonify({"message":"Harap verifikasi email terlebih dahulu!!"}), 403
    
    # Autentikasi berhasil, generate token akses JWT
    access_token = create_access_token(identity=str(user['_id']))
    
    return jsonify({
        "access_token": access_token,
    
    }), 200

blacklist_collection = db['blacklist']

def is_token_blacklisted(jti):
    return blacklist_collection.find_one({"jti": jti}) is not None

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return is_token_blacklisted(jti)

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti =  get_jwt_identity()
    blacklist_collection.insert_one({"jti": jti})
    return jsonify({"message": "Logout berhasil"}), 200
    
    
    
@app.get("/myprofile")
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    user = collection.find_one({"_id": ObjectId(current_user)})
    
    if user:
        return jsonify(
            id=str(user['_id']),
            email=user['email'],
            name=user['name']
        ), 200
    else:
        return jsonify({"message": "User not found"}), 404

@app.get("/who")
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    user = collection.find_one({"_id": ObjectId(current_user)})
    if user:
        return jsonify(
            id=str(user['_id']),
            email=user['email'],
            name=user['name']
        ), 200
    else:
        return jsonify({"message": "User not found"}), 404



@app.route('/api/save_user', methods=['POST'])
def save_user():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    email = data.get('email')
    name = data.get('name')
    google_id = data.get('google_id')

        # Query user dari MongoDB
    user_data = collection.find_one({"email": email})
     
    # Menghasilkan JWT token
    access_token = create_access_token(identity=str(user_data['_id']))
    
    if not email or not name or not google_id:
        return jsonify({"error": "Incomplete data"}), 400

    
    return {
        "token_access": access_token,
        "user_id": str(user_data['_id']),
        "name": user_data['name'],
        "email": user_data['email']
    }, 200
    
    return jsonify({"message": "User saved successfully $access_token"}), 201

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    email = data.get('email')
    name = data.get('name')
    google_id = data.get('google_id')
    
    if not email or not name or not google_id:
        return jsonify({"error": "Incomplete data"}), 400

    # Check if the user already exists
    if collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 200
    
    # Insert new user data
    user_data = {
        "email": email,
        "name": name,
        "google_id": google_id
    }
    collection.insert_one(user_data)
    
    return jsonify({"message": "User saved successfully"}), 201


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'image' not in request.files:
            return jsonify({"message": "No file part"}), 400
        file = request.files['image']
        if file.filename == '':
            return jsonify({"message": "No selected file"}), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Simpan metadata file ke MongoDB
            file_metadata = {
                "filename": filename,
                "file_path": file_path,
                "content_type": file.content_type
            }
            collection.insert_one(file_metadata)
            
            return jsonify({"message": "success", "file_path": file_path}), 200
        else:
            return jsonify({"message": "File type not allowed"}), 400
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=image>
      <input type=submit value=Upload>
    </form>
    '''




@app.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    logging.info(f"Updating profile for user_id: {user_id}")
    data = request.get_json()

    if not data:
        return jsonify({"message": "No input data provided"}), 400

    new_fullname = data.get('name')
    new_email = data.get('email')



    if not new_fullname and not new_email:
        return jsonify({"message": "Fullname and email are required"}), 400

    # Pastikan user dengan user_id ada di database
    user = collection.find_one({"_id": ObjectId(user_id)})

    print(user)

    if not user:
        return jsonify({"message": "User not found"}), 404

    # Lakukan pembaruan profil
    result = collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"name": new_fullname, "email": new_email}}
    )

    if result.modified_count == 1:
        # Jika pembaruan berhasil, ambil data pengguna yang diperbarui
        updated_user = collection.find_one({"_id": ObjectId(user_id)})
        return jsonify({
            "message": "Profile updated successfully",
            "user_id": str(updated_user['_id']),
            "name": updated_user['name'],
            "email": updated_user['email']
        }), 200
    else:
        # Jika tidak ada perubahan yang dilakukan
        return jsonify({"message": "Failed to update profile"}), 500




@app.route('/update_password', methods=['PUT'])
@jwt_required()
def update_password():
    user_id = get_jwt_identity()
    data = request.get_json()

    if not data:
        return jsonify({"message": "No input data provided"}), 400

    password_baru = data.get('password_baru')
    konfirmasi_password = data.get('konfirmasi_password')

    if not password_baru or not konfirmasi_password:
        return jsonify({"message": "Old password and new password are required"}), 400

    user = collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"message": "User not found"}), 404

    hashed_new_password = argon2.hash(password_baru)

    collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password": hashed_new_password}}
    )

    return jsonify({"message": "Password updated successfully"}), 200


# # Tambahkan koleksi blacklist
# blacklist_collection = db['blacklist']

# # Fungsi untuk memeriksa apakah token diblacklist
# def is_token_blacklisted(jti):
#     return blacklist_collection.find_one({"jti": jti}) is not None

# # Tambahkan callback untuk memeriksa token pada setiap permintaan
# @jwt.token_in_blocklist_loader
# def check_if_token_in_blacklist(jwt_header, jwt_payload):
#     jti = jwt_payload["jti"]
#     return is_token_blacklisted(jti)

# @app.route('/logout', methods=['POST'])
# @jwt_required()
# def logout():
#     jti = get_jwt_identity()["jti"]
#     blacklist_collection.insert_one({"jti": jti})
#     return jsonify({"message": "Logout berhasil"}), 200



region_of_interest = [(300, 20), (302, 680), (280, 680), (280, 20)]
classes_names = model.names  # Assuming model.names provides the classes names as a list
counter = object_counter.ObjectCounter()
counter.set_args(view_img=True, reg_pts=region_of_interest, classes_names=classes_names, draw_tracks=True)



lokasi = ""

# Realtime Object Detection & Counting
@app.route('/realtime/<data>')
def index(data):
    global lokasi
    lokasi = data
    return render_template('video.html')

@app.route('/video_feed')
def video_feed():
    return Response(count_object(), mimetype='multipart/x-mixed-replace; boundary=frame')

def count_object():
    cap = cv2.VideoCapture('data/video.mp4')
    assert cap.isOpened()
    tracked_ids = set()
    
    while True:
        success, im0 = cap.read()
        if not success:
            break
        
        tracks = model.track(im0, persist=True, show=False)
        im0 = counter.start_counting(im0, tracks)
        
        # Process tracks and save to MongoDB if crossing the ROI
        if tracks[0].boxes.id is not None:
            boxes = tracks[0].boxes.xyxy.cpu()
            clss = tracks[0].boxes.cls.cpu().tolist()
            track_ids = tracks[0].boxes.id.int().cpu().tolist()

            for box, track_id, cls in zip(boxes, track_ids, clss):
                if track_id not in tracked_ids:
                    prev_position = counter.track_history[track_id][-2] if len(counter.track_history[track_id]) > 1 else None
                    current_position = (float((box[0] + box[2]) / 2), float((box[1] + box[3]) / 2))
                    
                    if len(region_of_interest) >= 3:
                        counting_region = Polygon(region_of_interest)
                        is_inside = counting_region.contains(Point(current_position))
                        
                        if prev_position and is_inside:
                            tracked_ids.add(track_id)
                            direction = "IN" if (box[0] - prev_position[0]) * (counting_region.centroid.x - prev_position[0]) > 0 else "OUT"
                            now = datetime.now()
                            date = now.date().isoformat()
                            day_name = now.strftime('%A')
                            counts = {model.names[cls]: 1}
                            global lokasi

                            detection = {
                                "day": day_name,
                                "lokasi": lokasi,
                                "date": date,
                                "counts": counts
                            }
                            collection2.update_one(
                            {'date': str(date), 'day': day_name, 'lokasi': lokasi},
                            {'$inc': {f'counts.{key}': value for key, value in counts.items()},
                            '$setOnInsert': {'date': str(date), 'day': day_name, 'lokasi': lokasi}},
                            upsert=True
                            )

        ret, buffer = cv2.imencode('.jpg', im0)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    cap.release()

if __name__ == '__main__':
	app.run(debug=True)
