from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from datetime import timedelta
import os

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin123@localhost:5432/secureaccess_pro'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# ===================================================
# DATABASE MODELS
# ===================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    role = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    action = db.Column(db.String(100))
    resource = db.Column(db.String(100))
    status = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    login_time = db.Column(db.DateTime, server_default=db.func.now())
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(20))
    failure_reason = db.Column(db.String(100))

class SiteAccess(db.Model):
    __tablename__ = 'site_access'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50))
    page_accessed = db.Column(db.String(100))
    access_time = db.Column(db.DateTime, server_default=db.func.now())
    user_agent = db.Column(db.String(500))
    status = db.Column(db.String(20))

# ===================================================
# TRACK SITE ACCESS (Before every request)
# ===================================================

@app.before_request
def track_site_access():
    # Skip tracking for API endpoints to avoid infinite loop
    if request.endpoint in ['static', 'get_login_history', 'get_logs', 'get_site_access']:
        return None
    
    # Get client IP address
    ip_address = request.remote_addr
    
    # Get user agent (browser info)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Get page accessed
    page_accessed = request.path
    
    # Log site access
    try:
        access = SiteAccess(
            ip_address=ip_address,
            page_accessed=page_accessed,
            user_agent=user_agent[:500],
            status="VISITED"
        )
        db.session.add(access)
        db.session.commit()
    except Exception as e:
        print(f"Error logging site access: {e}")
        db.session.rollback()

# ===================================================
# ROUTES
# ===================================================

@app.route('/')
def home():
    return jsonify({"message": "SecureAccess Pro API is running"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    tfa_code = data.get('tfa_code')
    
    # Get client IP address
    ip_address = request.remote_addr
    
    # Check 2FA
    if tfa_code != '123456':
        # Log failed login due to 2FA
        history = LoginHistory(
            username=username,
            ip_address=ip_address,
            status="FAILED",
            failure_reason="Invalid 2FA code"
        )
        db.session.add(history)
        db.session.commit()
        return jsonify({"error": "Invalid 2FA code"}), 401
    
    # Find user
    user = User.query.filter_by(username=username).first()
    
    # Check password
    if user and password == user.password_hash:
        # Create access token with role claim
        access_token = create_access_token(
            identity=username,
            additional_claims={"role": user.role}
        )
        
        # Log successful login to login_history
        history = LoginHistory(
            username=username,
            ip_address=ip_address,
            status="SUCCESS",
            failure_reason=None
        )
        db.session.add(history)
        db.session.commit()
        
        # Log to access_logs
        log = AccessLog(
            username=username,
            action="LOGIN",
            resource="SYSTEM",
            status="SUCCESS"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "token": access_token,
            "username": username,
            "role": user.role
        }), 200
    
    # Log failed login (invalid credentials)
    history = LoginHistory(
        username=username,
        ip_address=ip_address,
        status="FAILED",
        failure_reason="Invalid username or password"
    )
    db.session.add(history)
    db.session.commit()
    
    log = AccessLog(
        username=username,
        action="LOGIN",
        resource="SYSTEM",
        status="FAILED"
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({"error": "Invalid credentials"}), 401

# ===================================================
# SIGN-UP / REGISTER ENDPOINT (NEW)
# ===================================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    confirm_password = data.get('confirm_password')
    
    # Validation
    if not username or not password or not email:
        return jsonify({"error": "All fields are required"}), 400
    
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    if '@' not in email or '.' not in email:
        return jsonify({"error": "Please enter a valid email address"}), 400
    
    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists. Please choose another."}), 409
    
    # Check if email already exists
    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        return jsonify({"error": "Email already registered. Please login or use another email."}), 409
    
    # Create new user (default role: "Viewer")
    new_user = User(
        username=username,
        password_hash=password,  # In production, hash this with bcrypt
        email=email,
        role="Viewer"  # Default role for new users
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        # Log the registration
        ip_address = request.remote_addr
        log = AccessLog(
            username=username,
            action="REGISTER",
            resource="SYSTEM",
            status="SUCCESS"
        )
        db.session.add(log)
        db.session.commit()
        
        # Also log to login_history
        history = LoginHistory(
            username=username,
            ip_address=ip_address,
            status="SUCCESS",
            failure_reason=None
        )
        db.session.add(history)
        db.session.commit()
        
        return jsonify({
            "message": "Registration successful! You can now login.",
            "username": username,
            "role": "Viewer"
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

# ===================================================
# PROTECTED ROUTES
# ===================================================

@app.route('/api/protected/hr', methods=['GET'])
@jwt_required()
def hr_portal():
    claims = get_jwt()
    username = get_jwt_identity()
    role = claims.get('role', '')
    
    if role in ['Administrator', 'Employee']:
        log = AccessLog(
            username=username,
            action="ACCESS",
            resource="HR Portal",
            status="GRANTED"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "message": "Welcome to HR Portal",
            "data": {"employees": 25, "departments": 5}
        })
    else:
        log = AccessLog(
            username=username,
            action="ACCESS",
            resource="HR Portal",
            status="DENIED"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({"error": "Access denied"}), 403

@app.route('/api/protected/finance', methods=['GET'])
@jwt_required()
def finance_dashboard():
    claims = get_jwt()
    username = get_jwt_identity()
    role = claims.get('role', '')
    
    if role == 'Administrator':
        log = AccessLog(
            username=username,
            action="ACCESS",
            resource="Finance Dashboard",
            status="GRANTED"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "message": "Welcome to Finance Dashboard",
            "data": {"revenue": 150000, "expenses": 75000}
        })
    else:
        log = AccessLog(
            username=username,
            action="ACCESS",
            resource="Finance Dashboard",
            status="DENIED"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({"error": "Access denied"}), 403

@app.route('/api/protected/documents', methods=['GET'])
@jwt_required()
def document_manager():
    claims = get_jwt()
    username = get_jwt_identity()
    role = claims.get('role', '')
    
    if role in ['Administrator', 'Employee', 'Viewer']:
        log = AccessLog(
            username=username,
            action="ACCESS",
            resource="Document Manager",
            status="GRANTED"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "message": "Welcome to Document Manager",
            "data": {"documents": 42, "folders": 7}
        })
    else:
        log = AccessLog(
            username=username,
            action="ACCESS",
            resource="Document Manager",
            status="DENIED"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({"error": "Access denied"}), 403

# ===================================================
# LOGS AND HISTORY ROUTES (ADMIN ONLY)
# ===================================================

@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    claims = get_jwt()
    role = claims.get('role', '')
    
    if role == 'Administrator':
        logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(50).all()
        return jsonify([{
            "username": log.username,
            "action": log.action,
            "resource": log.resource,
            "status": log.status,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None
        } for log in logs])
    else:
        return jsonify({"error": "Access denied"}), 403

@app.route('/api/login-history', methods=['GET'])
@jwt_required()
def get_login_history():
    claims = get_jwt()
    role = claims.get('role', '')
    
    # Only admins can view login history
    if role == 'Administrator':
        history = LoginHistory.query.order_by(LoginHistory.login_time.desc()).limit(100).all()
        return jsonify([{
            "username": h.username,
            "login_time": h.login_time.isoformat() if h.login_time else None,
            "ip_address": h.ip_address,
            "status": h.status,
            "failure_reason": h.failure_reason
        } for h in history])
    else:
        return jsonify({"error": "Access denied"}), 403

@app.route('/api/site-access', methods=['GET'])
@jwt_required()
def get_site_access():
    claims = get_jwt()
    role = claims.get('role', '')
    
    # Only admins can view site access logs
    if role == 'Administrator':
        access_logs = SiteAccess.query.order_by(SiteAccess.access_time.desc()).limit(100).all()
        return jsonify([{
            "ip_address": log.ip_address,
            "page_accessed": log.page_accessed,
            "access_time": log.access_time.isoformat() if log.access_time else None,
            "user_agent": log.user_agent,
            "status": log.status
        } for log in access_logs])
    else:
        return jsonify({"error": "Access denied"}), 403

# ===================================================
# RUN THE APP
# ===================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)