# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime
import firebase_admin
from firebase_admin import credentials, firestore, storage
import jwt  # PyJWT library
import base64

# --- Flask App Setup ---
app = Flask(__name__)
# IMPORTANT: For security, change this SECRET_KEY to something long and complex.
app.config['SECRET_KEY'] = 'change-this-to-a-very-long-and-random-secret-key'
CORS(app)

# --- Firebase Initialization ---
try:
    # Ensure serviceAccountKey.json is in the same directory as app.py
    cred = credentials.Certificate("serviceAccountKey.json")
    
    # IMPORTANT: Replace 'your-project-id.appspot.com' with the URL from your Firebase Storage page.
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'your-project-id.appspot.com' 
    })
    
    # Connect to Firestore and Storage
    db = firestore.client()
    bucket = storage.bucket()
    print("✅ Firebase initialized successfully.")
except Exception as e:
    print(f"🔥 Firebase initialization failed: {e}")
    db = None
    bucket = None
# -----------------------------

# --- HTML Page Routes ---
@app.route('/')
def index():
    return render_template('index.html')

# --- API Routes ---

# 1. User Registration Route
@app.route('/api/register', methods=['POST'])
def register_user():
    if not db: return jsonify({'message': 'Database not connected.'}), 500
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'message': 'Name, Email, and Password are required.'}), 400

    email = data['email']
    password = data['password']
    name = data['name']
    
    users_ref = db.collection('users')
    
    # Check if this email already exists
    if users_ref.document(email).get().exists:
        return jsonify({'message': 'This Email is already registered.'}), 409

    # Securely hash the password
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    new_user = { 
        'name': name,
        'email': email, 
        'password_hash': hashed_password, 
        'created_at': datetime.datetime.utcnow().isoformat() 
    }
    users_ref.document(email).set(new_user)
    
    # Create a token to automatically log the user in after registration
    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24) # Token is valid for 24 hours
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({'message': 'User registered successfully!', 'token': token, 'name': name}), 201

# 2. User Login Route
@app.route('/api/login', methods=['POST'])
def login_user():
    if not db: return jsonify({'message': 'Database not connected.'}), 500
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and Password are required.'}), 400

    email, password = data['email'], data['password']
    user_doc_ref = db.collection('users').document(email)
    user_doc = user_doc_ref.get()

    if not user_doc.exists or not check_password_hash(user_doc.to_dict()['password_hash'], password):
        return jsonify({'message': 'Invalid Email or Password.'}), 401
    
    # Create a token if login is successful
    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    user_data = user_doc.to_dict()
    return jsonify({'message': 'Login successful!', 'token': token, 'name': user_data.get('name')}), 200

# 3. Token Verification Decorator for Protected Routes
def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # Header format is 'Bearer <token>'
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token: 
            return jsonify({'message': 'Authentication Token is missing!'}), 401
        
        try:
            # Verify the token is valid
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_email = data['email']
        except Exception:
            return jsonify({'message': 'Token is invalid or has expired!'}), 401
        
        return f(current_user_email, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# 4. Route to Submit a Report (Protected)
@app.route('/api/report', methods=['POST'])
@token_required
def handle_report(current_user_email):
    if not db or not bucket: return jsonify({'message': 'Database/Storage not connected.'}), 500
    
    data = request.get_json()
    if not data or not data.get('description') or not data.get('category') or not data.get('location'):
        return jsonify({'message': 'Required information is missing.'}), 400
    
    image_data_url = data.get('photo')
    image_url = ''
    
    # Receive Base64 image and save to Firebase Storage
    if image_data_url and image_data_url.startswith('data:image'):
        try:
            header, encoded = image_data_url.split(",", 1)
            image_format = header.split("/")[1].split(";")[0]
            image_data = base64.b64decode(encoded)
            
            # Create a unique filename for the image
            image_filename = f"reports/{uuid.uuid4()}.{image_format}"
            blob = bucket.blob(image_filename)
            
            blob.upload_from_string(image_data, content_type=f'image/{image_format}')
            blob.make_public() # Make the image publicly accessible
            image_url = blob.public_url
        except Exception as e:
            print(f"🔥 Image upload failed: {e}")
            image_url = '' # Empty URL if there's an error
            
    report_id = str(uuid.uuid4())
    
    # Save the report to Firestore
    new_report = {
        'report_id': report_id,
        'description': data['description'],
        'category': data['category'],
        'location': data['location'],
        'place': data.get('place', 'Unknown'),
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'status': 'received', # The current status of the report
        'reported_by': current_user_email, # Who reported it?
        'photo_url': image_url # URL of the image
    }
    
    db.collection('reports').document(report_id).set(new_report)
    print(f"New report received from {current_user_email}: {report_id}")
    return jsonify({'message': 'Report submitted successfully!', 'report_id': report_id}), 201

# --- NEW FEATURE ---
# 5. Route to Update a Report's Status (Protected)
#    (புதிய வசதி: புகாரின் நிலையை மாற்றுவதற்கான வழி)
@app.route('/api/report/<string:report_id>/status', methods=['PATCH'])
@token_required
def update_report_status(current_user_email, report_id):
    if not db: return jsonify({'message': 'Database not connected.'}), 500

    data = request.get_json()
    new_status = data.get('status')

    if not new_status:
        return jsonify({'message': 'New status is required.'}), 400

    try:
        report_ref = db.collection('reports').document(report_id)
        
        # Check if the report exists before trying to update it
        if not report_ref.get().exists:
            return jsonify({'message': 'Report not found.'}), 404

        # Update the 'status' field of the document
        report_ref.update({'status': new_status})
        
        # In a real app, you might also log who changed the status and when
        # report_ref.update({'status_last_updated_by': current_user_email})

        print(f"Report {report_id} status updated to '{new_status}' by {current_user_email}")
        return jsonify({'message': f'Report status successfully updated to {new_status}.'}), 200

    except Exception as e:
        print(f"🔥 Failed to update status for report {report_id}: {e}")
        return jsonify({'message': 'Failed to update report status.'}), 500
# --- END OF NEW FEATURE ---

# 6. Route to Get All Reports (Public)
@app.route('/api/reports', methods=['GET'])
def get_reports():
    if not db: return jsonify({'message': 'Database not connected.'}), 500
    try:
        # Order reports with the newest ones first
        docs_stream = db.collection('reports').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        reports_list = [doc.to_dict() for doc in docs_stream]
        return jsonify(reports_list), 200
    except Exception as e:
        return jsonify({'message': f'Failed to retrieve reports: {e}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

