# backend.py

from flask import Flask, request, url_for, jsonify, render_template_string
from flask_pymongo import PyMongo
from flask_cors import CORS
from argon2 import PasswordHasher
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from datetime import timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.config["MONGO_URI"] = "mongodb://localhost:27017/myflask1"
mongo = PyMongo(app)

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

ph = PasswordHasher()

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='arif.samiaji19@gmail.com',  # Ganti dengan email Anda
    # Ganti dengan password aplikasi yang dihasilkan
    MAIL_PASSWORD='bogfntuqtgnvxnbv',
)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

# Definisikan model User dengan PyMongo
users = mongo.db.users

UPLOAD_FOLDER = '/path/to/uploads'  # Ganti dengan path tempat menyimpan gambar
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def home():
    return 'Selamat datang di aplikasi Flask saya!'


@app.post('/signup')
def signup():
    data = request.get_json()
    name = data["name"]
    email = data["email"]
    password = data["password"]

    if not email:
        return jsonify({"message": "Email harus diisi"}), 400

    hashed_password = ph.hash(password)
    new_user = {"name": name, "email": email, "password": hashed_password}
    users.insert_one(new_user)

    return jsonify({"message": "Berhasil mendaftar"}), 201


@app.post("/login")
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email dan kata sandi diperlukan!"}), 400

    user = users.find_one({"email": email})

    if not user or not ph.verify(user["password"], password):
        return jsonify({"message": "Email atau kata sandi salah!"}), 400

    access_token = create_access_token(identity=str(user["_id"]))
    return jsonify({"token_access": access_token}), 200


@app.get("/myprofile")
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = users.find_one({"_id": user_id})

    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan."}), 404

    return jsonify({"id": str(user["_id"]), "email": user["email"], "name": user["name"], "profile_picture": user.get("profile_picture", "")}), 200


@app.put("/updateprofile")
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = users.find_one({"_id": user_id})

    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan."}), 404

    data = request.json
    new_name = data.get("name")
    new_email = data.get("email")

    if not new_name or not new_email:
        return jsonify({"message": "Nama dan email harus diisi."}), 400

    users.update_one({"_id": user_id}, {
        "$set": {"name": new_name, "email": new_email}})

    return jsonify({"message": "Profil berhasil diperbarui."}), 200


@app.put("/changepassword")
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = users.find_one({"_id": user_id})

    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan."}), 404

    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"message": "Kata sandi lama dan baru harus diisi."}), 400

    if not ph.verify(user["password"], old_password):
        return jsonify({"message": "Kata sandi lama salah."}), 400

    hashed_new_password = ph.hash(new_password)
    users.update_one({"_id": user_id}, {
        "$set": {"password": hashed_new_password}})

    return jsonify({"message": "Kata sandi berhasil diperbarui."}), 200


@app.post("/forgotpassword")
def forgot_password():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"message": "Email harus diisi"}), 400

    user = users.find_one({"email": email})

    if not user:
        return jsonify({"message": "Email tidak ditemukan"}), 404

    token = s.dumps(email, salt='email-confirm')

    reset_password_url = url_for('reset_password', token=token, _external=True)
    email_body = render_template_string('''
        Hello {{ user["name"] }},
        
        Anda menerima email ini, karena kami menerima permintaan untuk mengatur ulang kata sandi akun Anda.
        
        Silakan klik tautan di bawah ini untuk mengatur ulang kata sandi Anda. Tautan ini akan kedaluwarsa dalam 1 jam.
        
        Reset your password: {{ reset_password_url }}
        
        Jika Anda tidak meminta pengaturan ulang kata sandi, abaikan email ini atau hubungi dukungan jika Anda memiliki pertanyaan.
        
        Untuk bantuan lebih lanjut, silakan hubungi tim dukungan kami di developer arifmrikiproject@gmail.com.
        
        Salam Hangat,
                                                                                                        
                                                                                                        
                                                                                                        
                                                                                                        Mriki_Project
    ''', user=user, reset_password_url=reset_password_url)

    msg = Message('Reset Kata Sandi Anda',
                  sender='arif.samiaji19@gmail.com', recipients=[email])
    msg.body = email_body
    mail.send(msg)

    return jsonify({"message": "Silakan cek email Anda untuk link reset kata sandi"}), 200


@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except (SignatureExpired, BadSignature):
        return jsonify({"message": "Link tidak valid atau telah kedaluwarsa"}), 400

    if request.method == 'POST':
        data = request.form
        new_password = data.get("new_password")

        if not new_password:
            return jsonify({"message": "Kata sandi baru harus diisi"}), 400

        hashed_new_password = ph.hash(new_password)
        users.update_one({"email": email}, {
                         "$set": {"password": hashed_new_password}})

        return jsonify({"message": "Kata sandi berhasil diperbarui"}), 200

    return '''
        <form action="" method="post">
            <input type="password" name="new_password" placeholder="Kata Sandi Baru">
            <input type="submit" value="Reset Kata Sandi">
        </form>
    '''


if __name__ == "__main__":
    app.run(debug=True, host="192.168.1.21")
