import urllib
import os
import datetime
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import jwt
from supabase import create_client

load_dotenv()

# --------------------------
# Flask app setup
# --------------------------
app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")

# --------------------------
# PostgreSQL (Supabase) config
# --------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,     # Always check connection before using
    "pool_recycle": 300        # Recycle connections every 5 minutes
}
db = SQLAlchemy(app)

# --------------------------
# Supabase storage setup
# --------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --------------------------
# Allowed file types
# --------------------------
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --------------------------
# Models
# --------------------------
class Dog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    breed = db.Column(db.String(50), nullable=False)
    dog_type = db.Column(db.String(10), nullable=False)
    standard_img = db.Column(db.String(200), nullable=True)
    premium_img = db.Column(db.String(200), nullable=True)
    champion_img = db.Column(db.String(200), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "breed": self.breed,
            "dog_type": self.dog_type,
            "images": {
                "standard": self.standard_img,
                "premium": self.premium_img,
                "champion": self.champion_img
            }
        }
    
class Cat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    breed = db.Column(db.String(50), nullable=False)
    cat_type = db.Column(db.String(10), nullable=False)
    standard_img = db.Column(db.String(200), nullable=True)
    premium_img = db.Column(db.String(200), nullable=True)
    champion_img = db.Column(db.String(200), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "breed": self.breed,
            "cat_type": self.cat_type,
            "images": {
                "standard": self.standard_img,
                "premium": self.premium_img,
                "champion": self.champion_img
            }
        }


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    whatsapp_number = db.Column(db.String(15), nullable=False)
    location = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    pin_code = db.Column(db.String(10), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

    preferred_pet_type = db.Column(db.String(100), nullable=True)
    reason_for_liking_pets = db.Column(db.String(255), nullable=True)
    pet_qualities_preference = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --------------------------
# Auth decorators
# --------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split()[1]
            except IndexError:
                return jsonify({"error": "Token format invalid"}), 401
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except:
            return jsonify({"error": "Token invalid"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# --------------------------
# Supabase helper
# --------------------------
def upload_to_supabase(file_obj, filename):
    if file_obj and allowed_file(filename):
        try:
            file_bytes = file_obj.read()
            file_obj.seek(0)

            # ✅ fix: "true" as string, not boolean
            supabase.storage.from_(SUPABASE_BUCKET).upload(
                filename,
                file_bytes,
                {"upsert": "true"}   # or just remove this line if not needed
            )

            return supabase.storage.from_(SUPABASE_BUCKET).get_public_url(filename)
        except Exception as e:
            print(f"Upload error: {e}")
            return None
    return None

# Helper to extract Supabase storage path from public URL
def extract_storage_path(img_url: str) -> str:
    """
    Extract the file path inside the Supabase bucket from the public URL.
    Example:
        https://xyz.supabase.co/storage/v1/object/public/bucket-name/folder/file.png?token=...
        -> folder/file.png
    """
    try:
        # Everything after /<bucket_name>/ in URL before any query params
        return img_url.split(f"/{SUPABASE_BUCKET}/", 1)[1].split("?")[0]
    except IndexError:
        # fallback to just filename
        return img_url.split("/")[-1].split("?")[0]



# --------------------------
# Routes
# --------------------------
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json

    # Trim all string inputs
    username = data.get('username', '').strip()
    name = data.get('name', '').strip()
    contact_number = data.get('contact_number', '').strip()
    whatsapp_number = data.get('whatsapp_number', '').strip()
    location = data.get('location', '').strip() if data.get('location') else None
    address = data.get('address', '').strip() if data.get('address') else None
    pin_code = data.get('pin_code', '').strip() if data.get('pin_code') else None
    password = data.get('password', '').strip()

    # Check if username already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 400

    user = User(
        username=username,
        name=name,
        contact_number=contact_number,
        whatsapp_number=whatsapp_number,
        location=location,
        address=address,
        pin_code=pin_code,
        is_admin=False
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"})

@app.route('/user/questionnaire', methods=['POST'])
@token_required
def user_questionnaire(current_user):
    """
    Collects user preferences about pets after signup
    Questions:
    1. Which type of pet do you like?
    2. Why do you like pets?
    3. What qualities do you look for in a pet?
    """
    data = request.json
    preferred_pet_type = data.get('preferred_pet_type')
    reason_for_liking_pets = data.get('reason_for_liking_pets')
    pet_qualities_preference = data.get('pet_qualities_preference')

    if not all([preferred_pet_type, reason_for_liking_pets, pet_qualities_preference]):
        return jsonify({"error": "All questions must be answered"}), 400

    # Save answers to the user record
    current_user.preferred_pet_type = preferred_pet_type
    current_user.reason_for_liking_pets = reason_for_liking_pets
    current_user.pet_qualities_preference = pet_qualities_preference
    db.session.commit()

    return jsonify({
        "message": "Questionnaire submitted successfully",
        "answers": {
            "preferred_pet_type": preferred_pet_type,
            "reason_for_liking_pets": reason_for_liking_pets,
            "pet_qualities_preference": pet_qualities_preference
        }
    })


@app.route('/login', methods=['POST'])
def login():
    data = request.json

    # Trim username and password
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    print("LOGIN ATTEMPT:", {"username": username, "password": password})  # DEBUG

    user = User.query.filter_by(username=username).first()
    if user:
        print("Found user:", user.username)
    else:
        print("User not found")

    if user and user.check_password(password):
        print("Password correct")
        token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "Login successful", "token": token})

    print("Invalid credentials")
    return jsonify({"error": "Invalid credentials"}), 401


@app.route('/admin/signup', methods=['POST'])
def admin_signup():
    data = request.json
    if User.query.filter(or_(User.username == data.get('username'), User.email == data.get('email'))).first():
        return jsonify({"error": "Username or email exists"}), 400
    user = User(
        username=data.get('username'),
        email=data.get('email'),
        name=data.get('username'),
        contact_number="0000000000",
        whatsapp_number="0000000000",
        is_admin=True
    )
    user.set_password(data.get('password'))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Admin registered successfully"})

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    user = User.query.filter_by(username=data.get('username'), is_admin=True).first()
    if user and user.check_password(data.get('password')):
        token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({
            "message": "Admin login successful",
            "token": token,
            "admin": {
                "id": user.id,
                "username": user.username,
                "email": user.email
            }
        })
    return jsonify({"error": "Invalid admin credentials"}), 401


# Verify admin endpoint
@app.route('/admin/verify', methods=['GET'])
@token_required
@admin_required
def verify_admin(current_user):
    return jsonify({
        'success': True,
        'admin': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email
        }
    }), 200

# Add Dog
@app.route('/dog', methods=['POST'])
@token_required
@admin_required
def add_dog(current_user):
    data = request.form
    breed = data.get('breed')
    dog_type = data.get('dog_type')

    standard_img_file = request.files.get('standard_img')
    premium_img_file = request.files.get('premium_img')
    champion_img_file = request.files.get('champion_img')

    standard_img_url = upload_to_supabase(standard_img_file, secure_filename(standard_img_file.filename)) if standard_img_file else None
    premium_img_url = upload_to_supabase(premium_img_file, secure_filename(premium_img_file.filename)) if premium_img_file else None
    champion_img_url = upload_to_supabase(champion_img_file, secure_filename(champion_img_file.filename)) if champion_img_file else None

    new_dog = Dog(
        breed=breed,
        dog_type=dog_type,
        standard_img=standard_img_url,
        premium_img=premium_img_url,
        champion_img=champion_img_url
    )
    db.session.add(new_dog)
    db.session.commit()
    return jsonify({"message": "Dog added successfully", "dog": new_dog.to_dict()})

# Update Dog images
@app.route('/dog/<string:breed>/<string:dog_type>', methods=['PUT'])
@token_required
@admin_required
def update_dog_images(current_user, breed, dog_type):
    dog = Dog.query.filter_by(breed=breed, dog_type=dog_type).first()
    if not dog:
        return jsonify({"error": "Dog not found"}), 404

    standard_img_file = request.files.get('standard_img')
    premium_img_file = request.files.get('premium_img')
    champion_img_file = request.files.get('champion_img')

    if standard_img_file:
        dog.standard_img = upload_to_supabase(standard_img_file, secure_filename(standard_img_file.filename))
    if premium_img_file:
        dog.premium_img = upload_to_supabase(premium_img_file, secure_filename(premium_img_file.filename))
    if champion_img_file:
        dog.champion_img = upload_to_supabase(champion_img_file, secure_filename(champion_img_file.filename))

    db.session.commit()
    return jsonify({"message": "Dog images updated", "dog": dog.to_dict()})

# Delete all dogs of a given breed (Admins only)
@app.route('/dog/<string:breed>', methods=['DELETE'])
@token_required
@admin_required
def delete_dog(current_user, breed):
    dogs = Dog.query.filter_by(breed=breed).all()
    if not dogs:
        return jsonify({"error": f"No dogs found with breed '{breed}'"}), 404

    deleted_count = 0
    for dog in dogs:
        # delete images from Supabase if they exist
        for img_url in [dog.standard_img, dog.premium_img, dog.champion_img]:
            if img_url:
                try:
                    path = extract_storage_path(img_url)
                    supabase.storage.from_(SUPABASE_BUCKET).remove([path])
                except Exception as e:
                    print(f"Failed to delete {img_url}: {e}")

        db.session.delete(dog)
        deleted_count += 1

    db.session.commit()
    return jsonify({"message": f"Deleted {deleted_count} '{breed}' entries successfully"})


# Delete a specific dog entry by breed and dog_type (Admins only)
@app.route('/dog/<string:breed>/<string:dog_type>', methods=['DELETE'])
@token_required
@admin_required
def delete_dog_by_type(current_user, breed, dog_type):
    dog = Dog.query.filter_by(breed=breed, dog_type=dog_type).first()
    if not dog:
        return jsonify({"error": f"No dog found with breed '{breed}' and type '{dog_type}'"}), 404

    # delete images from Supabase if they exist
    for img_url in [dog.standard_img, dog.premium_img, dog.champion_img]:
        if img_url:
            try:
                path = extract_storage_path(img_url)
                supabase.storage.from_(SUPABASE_BUCKET).remove([path])
            except Exception as e:
                print(f"Failed to delete {img_url}: {e}")

    db.session.delete(dog)
    db.session.commit()
    return jsonify({"message": f"Deleted '{breed}' ({dog_type}) entry successfully"})


# List dogs (admin)
@app.route('/dogs', methods=['GET'])
@token_required
def list_dogs(current_user):
    dogs = Dog.query.all()
    return jsonify([dog.to_dict() for dog in dogs])

# Public dogs
@app.route('/public/dogs', methods=['GET'])
def public_list_dogs():
    dogs = Dog.query.all()
    return jsonify([dog.to_dict() for dog in dogs])

# Get dog by breed/type
@app.route('/dog', methods=['GET'])
@token_required
def get_dog(current_user):
    breed = request.args.get("breed")
    dog_type = request.args.get("dog_type")
    dog = Dog.query.filter_by(breed=breed, dog_type=dog_type).first()
    if not dog:
        return jsonify({"error": "Dog not found"}), 404
    return jsonify(dog.to_dict())

@app.route('/cat', methods=['POST'])
@token_required
@admin_required
def add_cat(current_user):
    data = request.form
    breed = data.get('breed')
    cat_type = data.get('cat_type')

    standard_img_file = request.files.get('standard_img')
    premium_img_file = request.files.get('premium_img')
    champion_img_file = request.files.get('champion_img')

    standard_img_url = upload_to_supabase(standard_img_file, secure_filename(standard_img_file.filename)) if standard_img_file else None
    premium_img_url = upload_to_supabase(premium_img_file, secure_filename(premium_img_file.filename)) if premium_img_file else None
    champion_img_url = upload_to_supabase(champion_img_file, secure_filename(champion_img_file.filename)) if champion_img_file else None

    new_cat = Cat(
        breed=breed,
        cat_type=cat_type,
        standard_img=standard_img_url,
        premium_img=premium_img_url,
        champion_img=champion_img_url
    )
    db.session.add(new_cat)
    db.session.commit()
    return jsonify({"message": "Cat added successfully", "cat": new_cat.to_dict()})
@app.route('/cat/<string:breed>/<string:cat_type>', methods=['PUT'])
@token_required
@admin_required
def update_cat_images(current_user, breed, cat_type):
    cat = Cat.query.filter_by(breed=breed, cat_type=cat_type).first()
    if not cat:
        return jsonify({"error": "Cat not found"}), 404

    standard_img_file = request.files.get('standard_img')
    premium_img_file = request.files.get('premium_img')
    champion_img_file = request.files.get('champion_img')

    if standard_img_file:
        cat.standard_img = upload_to_supabase(standard_img_file, secure_filename(standard_img_file.filename))
    if premium_img_file:
        cat.premium_img = upload_to_supabase(premium_img_file, secure_filename(premium_img_file.filename))
    if champion_img_file:
        cat.champion_img = upload_to_supabase(champion_img_file, secure_filename(champion_img_file.filename))

    db.session.commit()
    return jsonify({"message": "Cat images updated", "cat": cat.to_dict()})
@app.route('/cat/<string:breed>', methods=['DELETE'])
@token_required
@admin_required
def delete_cat(current_user, breed):
    cats = Cat.query.filter_by(breed=breed).all()
    if not cats:
        return jsonify({"error": f"No cats found with breed '{breed}'"}), 404

    deleted_count = 0
    for cat in cats:
        for img_url in [cat.standard_img, cat.premium_img, cat.champion_img]:
            if img_url:
                try:
                    path = extract_storage_path(img_url)
                    supabase.storage.from_(SUPABASE_BUCKET).remove([path])
                except Exception as e:
                    print(f"Failed to delete {img_url}: {e}")

        db.session.delete(cat)
        deleted_count += 1

    db.session.commit()
    return jsonify({"message": f"Deleted {deleted_count} '{breed}' entries successfully"})
@app.route('/cat/<string:breed>/<string:cat_type>', methods=['DELETE'])
@token_required
@admin_required
def delete_cat_by_type(current_user, breed, cat_type):
    cat = Cat.query.filter_by(breed=breed, cat_type=cat_type).first()
    if not cat:
        return jsonify({"error": f"No cat found with breed '{breed}' and type '{cat_type}'"}), 404

    for img_url in [cat.standard_img, cat.premium_img, cat.champion_img]:
        if img_url:
            try:
                path = extract_storage_path(img_url)
                supabase.storage.from_(SUPABASE_BUCKET).remove([path])
            except Exception as e:
                print(f"Failed to delete {img_url}: {e}")

    db.session.delete(cat)
    db.session.commit()
    return jsonify({"message": f"Deleted '{breed}' ({cat_type}) entry successfully"})
@app.route('/cats', methods=['GET'])
@token_required
def list_cats(current_user):
    cats = Cat.query.all()
    return jsonify([cat.to_dict() for cat in cats])
@app.route('/public/cats', methods=['GET'])
def public_list_cats():
    cats = Cat.query.all()
    return jsonify([cat.to_dict() for cat in cats])
@app.route('/cat', methods=['GET'])
@token_required
def get_cat(current_user):
    breed = request.args.get("breed")
    cat_type = request.args.get("cat_type")
    cat = Cat.query.filter_by(breed=breed, cat_type=cat_type).first()
    if not cat:
        return jsonify({"error": "Cat not found"}), 404
    return jsonify(cat.to_dict())

@app.route('/interest', methods=['POST']) 
@token_required 
def express_interest(current_user): 
    data = request.json 
    dog_id = data.get('dog_id') 
    line = data.get('line') 
    dog = Dog.query.get(dog_id)
    if not dog: return jsonify({"error": "Dog not found"}), 404
    location_text = current_user.location or "Unknown"
    address_text = current_user.address or "Not Provided"
    # Encode full address for Google Maps (%20 for spaces)
    full_address = f"{address_text}, {location_text}"
    encoded_maps_query = urllib.parse.quote(full_address, safe='')  # spaces -> %20
    google_maps_link = f"https://www.google.com/maps?q={encoded_maps_query}"
    # Professional multi-line WhatsApp message
    message = (
        f"Hello,\n\n"
        f"My name is {current_user.name}.\n"
        f"I am very interested in acquiring your {dog.breed} ({dog.dog_type}) - {line} line.\n\n"
        f"Here are my contact details:\n"
        f"• Contact Number: {current_user.contact_number}\n"
        f"• WhatsApp: {current_user.whatsapp_number}\n"
        f"• Location & Address: {full_address}\n\n"
        f"You can view my location here: {google_maps_link}\n\n"
        "Kindly let me know the next steps and any additional requirements.\n"
        "I look forward to your response. Thank you very much."
    )
    # URL-encode full message for WhatsApp
    encoded_message = urllib.parse.quote(message, safe='')  # encode all special chars
    whatsapp_number = "916381352158"
    whatsapp_link = f"https://wa.me/{whatsapp_number}?text={encoded_message}"
    return jsonify({
        "message": f"Interest recorded for {dog.breed} ({line})",
        "whatsapp_link": whatsapp_link,
        "debug_message": message
    })

@app.route('/interest/cat', methods=['POST'])
@token_required
def express_cat_interest(current_user):
    data = request.json 
    cat_id = data.get('cat_id')
    line = data.get('line')

    cat = Cat.query.get(cat_id)
    if not cat:
        return jsonify({"error": "Cat not found"}), 404

    location_text = current_user.location or "Unknown"
    address_text = current_user.address or "Not Provided"

    # Encode full address for Google Maps
    full_address = f"{address_text}, {location_text}"
    encoded_maps_query = urllib.parse.quote(full_address, safe='')
    google_maps_link = f"https://www.google.com/maps?q={encoded_maps_query}"

    # WhatsApp message for Cat
    message = (
        f"Hello,\n\n"
        f"My name is {current_user.name}.\n"
        f"I am very interested in acquiring your {cat.breed} ({cat.cat_type}) - {line} line.\n\n"
        f"Here are my contact details:\n"
        f"• Contact Number: {current_user.contact_number}\n"
        f"• WhatsApp: {current_user.whatsapp_number}\n"
        f"• Location & Address: {full_address}\n\n"
        f"You can view my location here: {google_maps_link}\n\n"
        "Kindly let me know the next steps and any additional requirements.\n"
        "I look forward to your response. Thank you very much."
    )

    # Encode message
    encoded_message = urllib.parse.quote(message, safe='')
    whatsapp_number = "916381352158"
    whatsapp_link = f"https://wa.me/{whatsapp_number}?text={encoded_message}"

    return jsonify({
        "message": f"Interest recorded for {cat.breed} ({line})",
        "whatsapp_link": whatsapp_link,
        "debug_message": message
    })

# --------------------------
# Run server
# --------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # Replace 192.168.1.10 with your local IP
    app.run(host="0.0.0.0", port=5000, debug=True)
