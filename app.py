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

# --- Flask செயலியை அமைத்தல் ---
app = Flask(__name__)
# முக்கியம்: பாதுகாப்பு காரணங்களுக்காக இந்த SECRET_KEY-ஐ சிக்கலான, நீளமான ஒன்றாக மாற்றவும்.
app.config['SECRET_KEY'] = 'change-this-to-a-very-long-and-random-secret-key'
CORS(app)

# --- Firebase அமைத்தல் ---
try:
    # serviceAccountKey.json கோப்பு உங்கள் app.py இருக்கும் இடத்திலேயே இருக்க வேண்டும்.
    cred = credentials.Certificate("serviceAccountKey.json")
    
    # முக்கியம்: 'your-project-id.appspot.com' என்பதை உங்கள் Firebase Storage பக்கத்தில் உள்ள URL உடன் மாற்றவும்.
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'your-project-id.appspot.com' 
    })
    
    # Firestore மற்றும் Storage-ஐ இணைக்கிறோம்
    db = firestore.client()
    bucket = storage.bucket()
    print("✅ Firebase வெற்றிகரமாக இணைக்கப்பட்டது.")
except Exception as e:
    print(f"🔥 Firebase-ஐ இணைப்பதில் சிக்கல்: {e}")
    db = None
    bucket = None
# -----------------------------

# --- HTML பக்கங்களுக்கான வழிகள் (Routes) ---
@app.route('/')
def index():
    return render_template('index.html')

# இந்த வழிகள் உங்களுக்கு தனி login/register பக்கங்கள் இருந்தால் தேவை.
# @app.route('/login')
# def login_page():
#     return render_template('login.html')

# @app.route('/register')
# def register_page():
#     return render_template('register.html')

# --- API Routes ---

# 1. பயனர் பதிவு செய்வதற்கான வழி
@app.route('/api/register', methods=['POST'])
def register_user():
    if not db: return jsonify({'message': 'Database இணைக்கப்படவில்லை.'}), 500
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'message': 'Name, Email மற்றும் Password தேவை.'}), 400

    email = data['email']
    password = data['password']
    name = data['name']
    
    users_ref = db.collection('users')
    
    # இந்த email ஏற்கனவே உள்ளதா என சரிபார்க்கிறோம்
    if users_ref.document(email).get().exists:
        return jsonify({'message': 'இந்த Email ஏற்கனவே பதிவு செய்யப்பட்டுள்ளது.'}), 409

    # கடவுச்சொல்லை பாதுகாப்பாக hash செய்கிறோம்
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    new_user = { 
        'name': name,
        'email': email, 
        'password_hash': hashed_password, 
        'created_at': datetime.datetime.utcnow().isoformat() 
    }
    users_ref.document(email).set(new_user)
    
    # பதிவு செய்தவுடன், பயனரை தானாக உள்நுழைய வைக்க Token உருவாக்குகிறோம்
    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24) # 24 மணிநேரம் செல்லுபடியாகும்
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({'message': 'பயனர் வெற்றிகரமாக பதிவு செய்யப்பட்டார்!', 'token': token, 'name': name}), 201

# 2. பயனர் உள்நுழைவதற்கான வழி
@app.route('/api/login', methods=['POST'])
def login_user():
    if not db: return jsonify({'message': 'Database இணைக்கப்படவில்லை.'}), 500
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email மற்றும் Password தேவை.'}), 400

    email, password = data['email'], data['password']
    user_doc_ref = db.collection('users').document(email)
    user_doc = user_doc_ref.get()

    if not user_doc.exists or not check_password_hash(user_doc.to_dict()['password_hash'], password):
        return jsonify({'message': 'தவறான Email அல்லது Password.'}), 401
    
    # உள்நுழைவு வெற்றிகரமாக இருந்தால் Token உருவாக்குகிறோம்
    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    user_data = user_doc.to_dict()
    return jsonify({'message': 'உள்நுழைவு வெற்றி!', 'token': token, 'name': user_data.get('name')}), 200

# 3. பாதுகாக்கப்பட்ட வழிகளுக்கான Token சரிபார்ப்பு (Decorator)
def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # Header 'Bearer <token>' வடிவத்தில் இருக்கும்
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token: 
            return jsonify({'message': 'அங்கீகார Token இல்லை!'}), 401
        
        try:
            # Token சரியானதா என சரிபார்க்கிறோம்
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_email = data['email']
        except Exception:
            return jsonify({'message': 'Token தவறானது அல்லது காலாவதியானது!'}), 401
        
        return f(current_user_email, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# 4. புகார்களைப் பதிவு செய்வதற்கான வழி (பாதுகாக்கப்பட்டது)
@app.route('/api/report', methods=['POST'])
@token_required
def handle_report(current_user_email):
    if not db or not bucket: return jsonify({'message': 'Database/Storage இணைக்கப்படவில்லை.'}), 500
    
    data = request.get_json()
    if not data or not data.get('description') or not data.get('category') or not data.get('location'):
        return jsonify({'message': 'தேவையான വിവരங்கள் இல்லை.'}), 400
    
    image_data_url = data.get('photo')
    image_url = ''
    
    # Base64 படத்தைப் பெற்று Firebase Storage-ல் சேமிக்கிறோம்
    if image_data_url and image_data_url.startswith('data:image'):
        try:
            header, encoded = image_data_url.split(",", 1)
            image_format = header.split("/")[1].split(";")[0]
            image_data = base64.b64decode(encoded)
            
            # படத்திற்கு ஒரு தனித்துவமான பெயரை உருவாக்குகிறோம்
            image_filename = f"reports/{uuid.uuid4()}.{image_format}"
            blob = bucket.blob(image_filename)
            
            blob.upload_from_string(image_data, content_type=f'image/{image_format}')
            blob.make_public() # படத்தை பொதுவில் அணுகும்படி மாற்றுகிறோம்
            image_url = blob.public_url
        except Exception as e:
            print(f"🔥 படத்தைப் பதிவேற்றுவதில் சிக்கல்: {e}")
            image_url = '' # சிக்கல் ஏற்பட்டால் ખાલી URL
            
    report_id = str(uuid.uuid4())
    
    # புகாரை Firestore-ல் சேமிக்கிறோம்
    new_report = {
        'report_id': report_id,
        'description': data['description'],
        'category': data['category'],
        'location': data['location'],
        'place': data.get('place', 'தெரியவில்லை'),
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'status': 'received', # புகாரின் தற்போதைய நிலை
        'reported_by': current_user_email, # புகாரளித்தவர் யார்?
        'photo_url': image_url # படத்தின் URL
    }
    
    db.collection('reports').document(report_id).set(new_report)
    print(f"புதிய புகார் {current_user_email} மூலம் பெறப்பட்டது: {report_id}")
    return jsonify({'message': 'புகார் வெற்றிகரமாக சமர்ப்பிக்கப்பட்டது!', 'report_id': report_id}), 201

# 5. எல்லா புகார்களையும் பெறுவதற்கான வழி (பொது)
@app.route('/api/reports', methods=['GET'])
def get_reports():
    if not db: return jsonify({'message': 'Database இணைக்கப்படவில்லை.'}), 500
    try:
        # புகார்களை சமீபத்தியது முதலில் வருமாறு வரிசைப்படுத்துகிறோம்
        docs_stream = db.collection('reports').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        reports_list = [doc.to_dict() for doc in docs_stream]
        return jsonify(reports_list), 200
    except Exception as e:
        return jsonify({'message': f'புகார்களைப் பெறுவதில் சிக்கல்: {e}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)