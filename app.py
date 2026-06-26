import os
import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from jwt.algorithms import RSAAlgorithm
import requests
import json
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
    jsonify,
)
import mysql.connector

from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

load_dotenv()

# ──────────────────────────────────────────────
#  App Config
# ──────────────────────────────────────────────
app = Flask(__name__)

SECRET_KEY = os.environ.get("AGRICONNECT_SECRET", "agri-jwt-secret-2024-change-me")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip().strip('"')
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip().strip('"')
JWT_ALGORITHM = "HS256"
JWT_EXP_HOURS = 24  # token lives for 24 hours
COOKIE_NAME = "clerk_token"  # Use Clerk token cookie

# Clerk Integration Config
CLERK_PUBLISHABLE_KEY = os.environ.get("CLERK_PUBLISHABLE_KEY", "").strip().strip('"')
CLERK_SECRET_KEY = os.environ.get("CLERK_SECRET_KEY", "").strip().strip('"')
CLERK_FRONTEND_API = os.environ.get("CLERK_FRONTEND_API", "lucky-lark-96.clerk.accounts.dev").strip().strip('"')
CLERK_JWKS_URL = f"https://{CLERK_FRONTEND_API}/.well-known/jwks.json"

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads', 'posts')
MARKET_UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads', 'market')
MSG_UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads', 'messages')
# Ensure folders exist (Ignore if read-only filesystem, e.g. Vercel)
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(MSG_UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(MARKET_UPLOAD_FOLDER, exist_ok=True)
except Exception as e:
    print(f"[BOOT] Folder creation skipped (read-only): {e}")


# ──────────────────────────────────────────────
#  Database helpers
# ──────────────────────────────────────────────
# Matches the Implemention Plan: MYSQL_HOST, MYSQL_PORT, etc.
DB_CONFIG = {
    "host": os.environ.get("MYSQL_HOST") or os.environ.get("MYSQLHOST", "127.0.0.1"),
    "user": os.environ.get("MYSQL_USER") or os.environ.get("MYSQLUSER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD") or os.environ.get("MYSQLPASSWORD", "root"),
    "database": os.environ.get("MYSQL_DATABASE") or os.environ.get("MYSQLDATABASE", "agriconnect_db"),
    "port": int(os.environ.get("MYSQL_PORT") or os.environ.get("MYSQLPORT") or 3306),
    "charset": "utf8mb4",
    "connection_timeout": 10,
    "use_pure": True, # Force pure-python to avoid buggy C-extension issues on Windows
    "ssl_disabled": False if (os.environ.get("MYSQL_SSL_CA") or os.environ.get("MYSQLSSL") == "TRUE") else True
}


def get_db():
    """Return a new MySQL connection, or None if unavailable."""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        print(f"[PROD-DB] Critical Connection error: {e}")
        return None


def query(sql, params=(), one=False):
    """Execute a SELECT and return dict rows."""
    conn = get_db()
    if not conn:
        return None if one else []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params)
        return cur.fetchone() if one else cur.fetchall()
    except Exception as e:
        print(f"[PROD-DB] Query error: {e}")
        return None if one else []
    finally:
        if conn:
            conn.close()


def execute(sql, params=()):
    """Execute INSERT/UPDATE/DELETE; return lastrowid or -1 on error."""
    conn = get_db()
    if not conn:
        return -1
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    except mysql.connector.IntegrityError as e:
        print(f"[PROD-DB] Integrity error: {e}")
        return -2  # unique constraint violation
    except Exception as e:
        print(f"[PROD-DB] Execute error: {e}")
        return -1
    finally:
        if conn:
            conn.close()


# ──────────────────────────────────────────────
#  Error Handlers 
# ──────────────────────────────────────────────
@app.errorhandler(404)
def page_not_found(e):
    return render_template('not_found.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return "Oops! AgriConnect encountered a glitch. Check your database connection settings in the Vercel dashboard.", 500


@app.context_processor
def inject_clerk_config():
    return {
        "clerk_publishable_key": CLERK_PUBLISHABLE_KEY,
        "clerk_frontend_api": CLERK_FRONTEND_API,
    }


# ──────────────────────────────────────────────
#  Password helpers (SHA-256)
# ──────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()

def check_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed


# ──────────────────────────────────────────────
#  JWT helpers
# ──────────────────────────────────────────────
def create_token(user_id: int, username: str) -> str:
    payload = {
        "sub": user_id,
        "user": username,
        "jti": str(uuid.uuid4()),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXP_HOURS),
    }
    encoded = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    if isinstance(encoded, bytes):
        return encoded.decode('utf-8')
    return encoded


_jwks_cache = None

def get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        try:
            print(f"[CLERK] Fetching JWKS from {CLERK_JWKS_URL}...")
            resp = requests.get(CLERK_JWKS_URL, timeout=5)
            if resp.status_code == 200:
                _jwks_cache = resp.json()
                print("[CLERK] JWKS successfully cached.")
            else:
                print(f"[CLERK] Failed to fetch JWKS: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[CLERK] JWKS Fetch exception: {e}")
    return _jwks_cache


def verify_clerk_token(token: str):
    """Verify the Clerk JWT session token and return its payload, or None."""
    if not token:
        return None
    try:
        # 1. Unverified decode to find key ID (kid)
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            print("[CLERK] Token header missing 'kid'.")
            return None
            
        # 2. Get public key from JWKS
        jwks = get_jwks()
        if not jwks or "keys" not in jwks:
            print("[CLERK] No valid JWKS cached.")
            return None
            
        jwk = None
        for key in jwks["keys"]:
            if key.get("kid") == kid:
                jwk = key
                break
        if not jwk:
            print(f"[CLERK] Key {kid} not found in JWKS.")
            return None
            
        # 3. Load public key
        public_key = RSAAlgorithm.from_jwk(jwk)
        
        # 4. Decode and verify token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )
        return payload
    except Exception as e:
        print(f"[CLERK] Token verification error: {e}")
        return None


def get_current_user():
    """Verify Clerk session cookie, load or create the user in local MySQL DB, or fallback to mock user."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
        
    payload = verify_clerk_token(token)
    if not payload:
        return None
        
    clerk_id = payload.get("sub")
    if not clerk_id:
        return None
        
    # Helper to construct a mock/fallback user if database is disconnected
    def get_fallback_user():
        email = payload.get("email") or ""
        if not email:
            email = f"{clerk_id}@clerk.agriconnect.in"
            
        full_name = payload.get("name")
        if not full_name:
            first_name = payload.get("first_name") or ""
            last_name = payload.get("last_name") or ""
            full_name = f"{first_name} {last_name}".strip() or email.split("@")[0].capitalize() or "Clerk User"
            
        avatar_url = payload.get("picture") or payload.get("image_url") or f"https://ui-avatars.com/api/?name={full_name[0]}&background=1b873f&color=fff&rounded=true"
        username = email.split("@")[0].lower() or clerk_id.lower()
        
        return {
            "id": 0,
            "full_name": full_name,
            "username": username,
            "email": email,
            "title": "AgriConnect Member (Offline Mode)",
            "location": "India",
            "connections": 342,
            "avatar_url": avatar_url,
            "clerk_id": clerk_id
        }

    # 1. Try to load user from local database by clerk_id
    try:
        user = query("SELECT * FROM users WHERE clerk_id=%s AND is_active=1", (clerk_id,), one=True)
        if user:
            return user
    except Exception as e:
        print(f"[CLERK] Local DB query failed: {e}. Falling back to mock session.")
        return get_fallback_user()

    # 2. Sync / create user from Clerk API using CLERK_SECRET_KEY
    if not CLERK_SECRET_KEY:
        print("[CLERK] CLERK_SECRET_KEY not set. Falling back to local offline user.")
        return get_fallback_user()

    try:
        headers = {"Authorization": f"Bearer {CLERK_SECRET_KEY}"}
        resp = requests.get(f"https://api.clerk.com/v1/users/{clerk_id}", headers=headers, timeout=5)
        if resp.status_code != 200:
            print(f"[CLERK] API call failed: HTTP {resp.status_code}. Using fallback user.")
            return get_fallback_user()
            
        clerk_user = resp.json()
        
        email = ""
        if clerk_user.get("email_addresses"):
            email = clerk_user["email_addresses"][0].get("email_address", "")
        if not email:
            email = f"{clerk_id}@clerk.agriconnect.in"

        first_name = clerk_user.get("first_name") or ""
        last_name = clerk_user.get("last_name") or ""
        full_name = f"{first_name} {last_name}".strip() or "Clerk User"
        avatar_url = clerk_user.get("image_url") or clerk_user.get("profile_image_url") or ""
        
        username = clerk_user.get("username")
        if not username:
            username = email.split("@")[0].lower()

        # Ensure username uniqueness
        try:
            base_username = username
            counter = 1
            while query("SELECT id FROM users WHERE username=%s", (username,), one=True):
                username = f"{base_username}{counter}"
                counter += 1
        except:
            pass

        # Check if user already exists by email
        existing_user = query("SELECT * FROM users WHERE email=%s AND is_active=1", (email,), one=True)
        if existing_user:
            execute("UPDATE users SET clerk_id=%s, avatar_url=%s WHERE id=%s", (clerk_id, avatar_url or existing_user["avatar_url"], existing_user["id"]))
            return query("SELECT * FROM users WHERE id=%s", (existing_user["id"],), one=True)

        # Create new local user
        res = execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, title, location, avatar_url, clerk_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (full_name, username, email, "clerk-auth", "AgriConnect Member", "India", avatar_url, clerk_id)
        )
        if res > 0:
            return query("SELECT * FROM users WHERE id=%s", (res,), one=True)
            
    except Exception as e:
        print(f"[CLERK] Exception in syncing user profile: {e}")
        
    return get_fallback_user()


# ──────────────────────────────────────────────
#  Auth decorator
# ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login_page"))
        return f(*args, user=user, **kwargs)

    return decorated


# ──────────────────────────────────────────────
#  Fallback data  (used when DB is unavailable)
# ──────────────────────────────────────────────
DEMO_USER = {
    "id": 0,
    "full_name": "Demo Farmer",
    "username": "demo",
    "email": "demo@agriconnect.in",
    "title": "Organic Farmer & Agri-Tech Enthusiast",
    "location": "Andhra Pradesh, India",
    "connections": 342,
    "avatar_url": "https://ui-avatars.com/api/?name=D+F&background=1b873f&color=fff&rounded=true",

}

DEMO_POSTS = [
    {
        "author_name": "Rajesh Kumar",
        "author_title": "Traditional Wheat Farmer",
        "time_ago": "2 hours ago",
        "content": "Just finished testing the new drip irrigation system on the north field. The water savings are incredible! 🌾💧",
        "likes": 124,
        "comments": 18,
        "avatar_url": "https://ui-avatars.com/api/?name=RK&background=d4edda&color=1b5e20&rounded=true",
    },
    {
        "author_name": "Priya Verma",
        "author_title": "Organic Vegetable Grower",
        "time_ago": "5 hours ago",
        "content": "Started using neem oil spray instead of chemical pesticides. Pests are down 70%! 🌿✨",
        "likes": 89,
        "comments": 12,
        "avatar_url": "https://ui-avatars.com/api/?name=PV&background=fff3e0&color=e65100&rounded=true",
    },
]

DEMO_FRIENDS = [
    {
        "id": 2,
        "name": "Rajesh Kumar",
        "title": "Traditional Wheat Farmer",
        "avatar_url": "https://ui-avatars.com/api/?name=RK&background=d4edda&color=1b5e20&rounded=true",
    },
    {
        "id": 3,
        "name": "Priya Verma",
        "title": "Organic Vegetable Grower",
        "avatar_url": "https://ui-avatars.com/api/?name=PV&background=fff3e0&color=e65100&rounded=true",
    },
    {
        "id": 4,
        "name": "Amjad Khan",
        "title": "Paddy & Rice Specialist",
        "avatar_url": "https://ui-avatars.com/api/?name=AK&background=e8f5e9&color=2e7d32&rounded=true",
    },
    {
        "id": 5,
        "name": "Sunita Devi",
        "title": "Dairy & Cattle Farmer",
        "avatar_url": "https://ui-avatars.com/api/?name=SD&background=fce4ec&color=880e4f&rounded=true",
    },
    {
        "id": 6,
        "name": "Vikram Singh",
        "title": "Sugarcane Grower",
        "avatar_url": "https://ui-avatars.com/api/?name=VS&background=e3f2fd&color=1565c0&rounded=true",
    },
]

DEMO_SUGGESTIONS = [
    {
        "name": "Kiran Bhat",
        "title": "Coconut Farmer, Kerala",
        "avatar_url": "https://ui-avatars.com/api/?name=KB&background=e8f5e9&color=1b5e20&rounded=true",
    },
    {
        "name": "Mohan Das",
        "title": "Basmati Rice Grower, UP",
        "avatar_url": "https://ui-avatars.com/api/?name=MD&background=fff8e1&color=f57f17&rounded=true",
    },
    {
        "name": "Shalini Patel",
        "title": "Spice Farmer, Gujarat",
        "avatar_url": "https://ui-avatars.com/api/?name=SP&background=fce4ec&color=c62828&rounded=true",
    },
]

DEMO_LISTINGS = [
    {
        "category": "tractor", "listing_type": "rent", "title": "Mahindra JIVO 245 DI Tractor",
        "seller_name": "Ravi Shankar", "seller_location": "Punjab", "price": 1800, "price_unit": "/day",
        "image_url": "/static/agri/Mahindra JIVO 245 DI Tractor.avif", "description": "High performance compact tractor for small farms. 4WD, 24HP, 2023 Model."
    },
    {
        "category": "tractor", "listing_type": "sell", "title": "Sonalika GT 20 Mini Tractor",
        "seller_name": "Anand Kumar", "seller_location": "Haryana", "price": 340000, "price_unit": "",
        "image_url": "/static/agri/Sonalika GT 20 Mini Tractor.jpg", "description": "2WD mini tractor in good condition. 20HP engine."
    },
    {
        "category": "fertilizer", "listing_type": "sell", "title": "Vermicompost Fertilizer (50kg)",
        "seller_name": "GreenEarth Farms", "seller_location": "UP", "price": 420, "price_unit": "/bag",
        "image_url": "/static/agri/Vermicompost Fertilizer (50kg).jpg", "description": "100% Organic vermicompost for better soil health."
    },
    {
        "category": "fertilizer", "listing_type": "sell", "title": "DAP Fertilizer (50kg)",
        "seller_name": "Kisaan Store", "seller_location": "MP", "price": 1350, "price_unit": "/bag",
        "image_url": "/static/agri/DAP Fertilizer (50kg.jpg", "description": "NPK Rich fertilizer for vigorous crop growth."
    },
    {
        "category": "ghee", "listing_type": "sell", "title": "Pure Desi Cow Ghee (1L)",
        "seller_name": "Gopal Dairy", "seller_location": "Gujarat", "price": 850, "price_unit": "/litre",
        "image_url": "/static/agri/Pure Desi Cow Ghee (1L).webp", "description": "Traditional A2 Cow Ghee. No additives, purely handcrafted."
    },
    {
        "category": "ghee", "listing_type": "sell", "title": "Buffalo Ghee (500ml Jar)",
        "seller_name": "Farm Fresh", "seller_location": "Rajasthan", "price": 480, "price_unit": "/jar",
        "image_url": "/static/agri/Buffalo Ghee (500ml Jar).png", "description": "Premium Buffalo Ghee. Rich in nutrients and flavor."
    },
    {
        "category": "grain", "listing_type": "sell", "title": "Premium Wheat (Sharbati) 1 Quintal",
        "seller_name": "Rajesh Kumar", "seller_location": "Punjab", "price": 2200, "price_unit": "/quintal",
        "image_url": "/static/agri/Premium Wheat (Sharbati) 1 Quintal.jpg", "description": "Grade A Sharbati wheat, clean and high quality."
    },
    {
        "category": "grain", "listing_type": "sell", "title": "Basmati Rice (Long Grain) 50kg",
        "seller_name": "Mohan Das", "seller_location": "UP", "price": 4800, "price_unit": "/50kg",
        "image_url": "/static/agri/Basmati Rice (Long Grain) 50kg.jpg", "description": "Aged aromatic long grain basmati rice."
    },
    {
        "category": "crop", "listing_type": "sell", "title": "Fresh Tomato (Desi Hybrid) 10kg",
        "seller_name": "Suresh Farms", "seller_location": "Andhra Pradesh", "price": 320, "price_unit": "/10kg",
        "image_url": "/static/agri/Fresh Tomato (Desi Hybrid) 10kg.jpg", "description": "Freshly harvested pesticide-free tomatoes."
    },
    {
        "category": "crop", "listing_type": "sell", "title": "Red Onion 50kg Bag",
        "seller_name": "Kisaan Crop Co", "seller_location": "Maharashtra", "price": 1100, "price_unit": "/50kg",
        "image_url": "/static/agri/Red Onion 50kg Bag.jpg", "description": "Grade A red onions, ready for wholesale."
    }
]


def normalise_user(u: dict) -> dict:
    """Ensure avatar_url is always set."""
    if not u.get("avatar_url"):
        u["avatar_url"] = (
            f"https://ui-avatars.com/api/?name="
            f"{(u.get('full_name') or 'U')[0]}&background=1b873f&color=fff&rounded=true"
        )
    return u


def load_posts_db():
    rows = query("""
        SELECT p.*, u.full_name AS author_name, u.title AS author_title,
               u.avatar_url, p.created_at
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
        LIMIT 20
    """)
    if not rows:
        return DEMO_POSTS
    for p in rows:
        p["time_ago"] = "2 hours ago"
        if not p.get("avatar_url"):
            p["avatar_url"] = (
                f"https://ui-avatars.com/api/?name={p['author_name'][0]}&background=random&rounded=true"
            )
    return rows


# ══════════════════════════════════════════════
# ══════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════


@app.route("/login", methods=["GET"])
def login_page():
    if get_current_user():
        return redirect("/")
    return render_template(
        "login.html",
        clerk_publishable_key=CLERK_PUBLISHABLE_KEY,
        clerk_frontend_api=CLERK_FRONTEND_API
    )


@app.route("/register", methods=["GET"])
def register_page():
    if get_current_user():
        return redirect("/")
    return render_template(
        "register.html",
        clerk_publishable_key=CLERK_PUBLISHABLE_KEY,
        clerk_frontend_api=CLERK_FRONTEND_API
    )


@app.route("/logout")
def logout():
    """Clear clerk token cookie and redirect to login."""
    resp = make_response(redirect("/login"))
    resp.delete_cookie(COOKIE_NAME)
    return resp


# ══════════════════════════════════════════════
#  API ROUTES (Real-time Authentication)
# ══════════════════════════════════════════════


@app.route("/api/check-username")
def api_check_username():
    """Check if username is available."""
    username = request.args.get("username", "").strip().lower()
    if not username:
        return jsonify({"available": False, "message": "Username required"})

    if len(username) < 3:
        return jsonify(
            {"available": False, "message": "Username must be at least 3 characters"}
        )

    existing = query("SELECT id FROM users WHERE username=%s", (username,), one=True)
    return jsonify(
        {
            "available": existing is None,
            "message": "Username available"
            if existing is None
            else "Username already taken",
        }
    )


@app.route("/api/check-email")
def api_check_email():
    """Check if email is available."""
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"available": False, "message": "Email required"})

    if "@" not in email or "." not in email:
        return jsonify({"available": False, "message": "Invalid email format"})

    existing = query("SELECT id FROM users WHERE email=%s", (email,), one=True)
    return jsonify(
        {
            "available": existing is None,
            "message": "Email available"
            if existing is None
            else "Email already registered",
        }
    )


@app.route("/api/login", methods=["POST"])
def api_login():
    """JSON API for login - returns JSON response."""
    data = request.get_json() or {}
    email_or_user = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    remember = data.get("remember", False)

    if not email_or_user or not password:
        return jsonify(
            {"success": False, "message": "Email/username and password are required"}
        ), 400

    user = query(
        "SELECT * FROM users WHERE (email=%s OR username=%s) AND is_active=1",
        (email_or_user, email_or_user),
        one=True,
    )

    if user is None:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    if not check_password(password, user["password_hash"]):
        return jsonify({"success": False, "message": "Invalid password"}), 401

    execute("UPDATE users SET last_login=%s WHERE id=%s", (datetime.now(), user["id"]))

    token = create_token(user["id"], user["username"])
    max_age = JWT_EXP_HOURS * 3600 if remember else JWT_EXP_HOURS * 3600

    resp = make_response(
        jsonify(
            {
                "success": True,
                "message": "Login successful",
                "user": {
                    "id": user["id"],
                    "full_name": user["full_name"],
                    "username": user["username"],
                    "email": user["email"],
                    "avatar_url": user.get("avatar_url", ""),
                },
            }
        )
    )
    resp.set_cookie(COOKIE_NAME, token, httponly=True, secure=False, samesite="Lax", max_age=max_age)
    return resp


@app.route("/api/google-login", methods=["POST"])
def api_google_login():
    """JSON API for Google Login - verifying credential and returning a session."""
    data = request.get_json() or {}
    token = data.get("credential")

    if not token:
        return jsonify({"success": False, "message": "No credential provided"}), 400

    if not GOOGLE_CLIENT_ID:
        return jsonify({"success": False, "message": "Google Client ID not configured on server"}), 500

    try:
        # Verify the token with Google
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        
        email = idinfo.get("email", "").lower()
        full_name = idinfo.get("name", "Google User")
        avatar_url = idinfo.get("picture", "")

        if not email:
            return jsonify({"success": False, "message": "No email in Google token"}), 400

        # Check if user exists
        user = query("SELECT * FROM users WHERE email=%s AND is_active=1", (email,), one=True)
        
        if not user:
            # Implicit Registration
            base_username = email.split('@')[0].lower()
            username = base_username
            counter = 1
            while query("SELECT id FROM users WHERE username=%s", (username,), one=True):
                username = f"{base_username}{counter}"
                counter += 1
                
            pw_hash = hash_password(str(uuid.uuid4())) # Unusable random password
            
            result = execute(
                """INSERT INTO users
                   (full_name, username, email, password_hash, title, location, avatar_url)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (full_name, username, email, pw_hash, "AgriConnect Member", "Unknown", avatar_url)
            )
            if result < 0:
                return jsonify({"success": False, "message": "Failed to create user account"}), 500
            
            user_id = result
        else:
            user_id = user["id"]
            username = user["username"]
            execute("UPDATE users SET last_login=%s WHERE id=%s", (datetime.now(), user_id))

        app_token = create_token(user_id, username)
        
        resp = make_response(jsonify({"success": True, "message": "Google login successful"}))
        resp.set_cookie(COOKIE_NAME, app_token, httponly=True, secure=False, samesite="Lax", max_age=JWT_EXP_HOURS * 3600)
        return resp

    except ValueError:
        # Invalid token
        return jsonify({"success": False, "message": "Invalid Google token"}), 401


@app.route("/api/register", methods=["POST"])
def api_register():
    """JSON API for registration - returns JSON response."""
    data = request.get_json() or {}
    full_name = (data.get("full_name") or "").strip()
    username = (data.get("username") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    title = (data.get("title") or "").strip()
    location = (data.get("location") or "").strip()
    password = (data.get("password") or "").strip()
    confirm_pw = (data.get("confirm_password") or "").strip()

    if not all([full_name, username, email, password]):
        return jsonify(
            {"success": False, "message": "All required fields must be filled"}
        ), 400

    if len(username) < 3:
        return jsonify(
            {"success": False, "message": "Username must be at least 3 characters"}
        ), 400

    if len(password) < 6:
        return jsonify(
            {"success": False, "message": "Password must be at least 6 characters"}
        ), 400

    if password != confirm_pw:
        return jsonify({"success": False, "message": "Passwords do not match"}), 400

    existing_user = query(
        "SELECT id FROM users WHERE email=%s OR username=%s",
        (email, username),
        one=True,
    )
    if existing_user:
        return jsonify(
            {"success": False, "message": "Email or username already exists"}
        ), 400

    avatar_url = (
        f"https://ui-avatars.com/api/?name={full_name.replace(' ', '+')}"
        f"&background=1b873f&color=fff&rounded=true"
    )
    pw_hash = hash_password(password)

    result = execute(
        """INSERT INTO users
           (full_name, username, email, password_hash, title, location, avatar_url)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (full_name, username, email, pw_hash, title, location, avatar_url),
    )

    if result < 0:
        return jsonify(
            {"success": False, "message": "Registration failed. Please try again."}
        ), 500

    token = create_token(result, username)
    resp = make_response(
        jsonify(
            {
                "success": True,
                "message": "Registration successful",
                "user": {
                    "id": result,
                    "full_name": full_name,
                    "username": username,
                    "email": email,
                    "avatar_url": avatar_url,
                },
            }
        )
    )
    resp.set_cookie(
        COOKIE_NAME, token, httponly=True, max_age=JWT_EXP_HOURS * 3600, samesite="Lax"
    )
    return resp


@app.route("/api/me")
def api_me():
    """Get current user info."""
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False}), 401

    return jsonify(
        {
            "authenticated": True,
            "user": {
                "id": user["id"],
                "full_name": user["full_name"],
                "username": user["username"],
                "email": user.get("email", ""),
                "title": user.get("title", ""),
                "location": user.get("location", ""),
                "avatar_url": user.get("avatar_url", ""),
                "connections": user.get("connections", 0),
            },
        }
    )


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """JSON API for logout."""
    token = request.cookies.get(COOKIE_NAME)
    if token:
        payload = decode_token(token)
        if payload:
            execute(
                "INSERT IGNORE INTO revoked_tokens (jti) VALUES (%s)", (payload["jti"],)
            )

    resp = make_response(jsonify({"success": True, "message": "Logged out"}))
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.route("/api/account/delete", methods=["POST"])
@login_required
def api_delete_account(user):
    """Deactivate current user account and logout."""
    user = normalise_user(user)
    token = request.cookies.get(COOKIE_NAME)
    if token:
        payload = decode_token(token)
        if payload:
            execute("INSERT IGNORE INTO revoked_tokens (jti) VALUES (%s)", (payload["jti"],))

    execute("UPDATE users SET is_active=0 WHERE id=%s", (user['id'],))

    resp = make_response(jsonify({"success": True, "message": "Account deactivated"}))
    resp.delete_cookie(COOKIE_NAME)
    return resp


# ══════════════════════════════════════════════
#  PROTECTED PAGE ROUTES
# ══════════════════════════════════════════════


@app.route("/")
@login_required
def index(user):
    user = normalise_user(user)
    posts = load_posts_db()
    
    # 1. Fetch current friends (accepted connections)
    friends_rows = query(
        '''SELECT u.id, u.full_name AS name, u.title, u.avatar_url 
           FROM users u
           JOIN connections c ON (c.requester_id = u.id OR c.receiver_id = u.id)
           WHERE (c.requester_id = %s OR c.receiver_id = %s)
             AND u.id != %s
             AND c.status = "accepted"''',
        (user['id'], user['id'], user['id'])
    )
    friends = friends_rows if friends_rows else (DEMO_FRIENDS if user['id'] == 0 else [])
    
    # 2. Fetch suggestions (not the user, and not already connected)
    suggestions_rows = query(
        '''SELECT id, full_name AS name, title, avatar_url 
           FROM users 
           WHERE id != %s 
             AND id NOT IN (
                 SELECT requester_id FROM connections WHERE receiver_id = %s
                 UNION
                 SELECT receiver_id FROM connections WHERE requester_id = %s
             )
           LIMIT 3''',
        (user['id'], user['id'], user['id'])
    )
    suggestions = suggestions_rows if suggestions_rows else (DEMO_SUGGESTIONS if user['id'] == 0 else [])
    
    # 3. Active farmers count
    try:
        stats = query('SELECT COUNT(*) AS total FROM users WHERE is_active=1', one=True)
        total_users = stats['total'] if stats else (1 if user['id'] == 0 else 0)
    except:
        total_users = 1 if user['id'] == 0 else 0

    return render_template('index.html', user=user, posts=posts, suggestions=suggestions, friends=friends, total_users=total_users)


@app.route('/api/post/create', methods=['POST'])
@login_required
def api_create_post(user, post_id=None):
    user = normalise_user(user)
    content = request.form.get('content', '').strip()
    image = request.files.get('image')
    
    if not content and not image:
        return jsonify({'status': 'error', 'message': 'Post content cannot be empty'}), 400
        
    media_url = None
    media_type = None
    if image:
        # Preserve original file extension
        ext = 'jpg'
        if '.' in image.filename:
            ext = image.filename.rsplit('.', 1)[1].lower()
        
        # Determine media type
        video_exts = {'mp4', 'webm', 'ogg', 'mov', 'avi', 'mkv'}
        media_type = 'video' if ext in video_exts else 'image'
        
        filename = f"post_{user['id']}_{int(time.time())}.{ext}"
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(save_path)
        media_url = f"/static/uploads/posts/{filename}"
        
    res = execute(
        'INSERT INTO posts (user_id, content, media_url) VALUES (%s, %s, %s)',
        (user['id'], content, media_url)
    )
    
    if res > 0:
        return jsonify({'status': 'success', 'post_id': res, 'media_type': media_type})
    return jsonify({'status': 'error', 'message': 'Database error'}), 500


@app.route('/api/post/like/<int:post_id>', methods=['POST'])
@login_required
def api_like_post(user, post_id):
    user = normalise_user(user)
    liked = query('SELECT * FROM post_likes WHERE user_id=%s AND post_id=%s', (user['id'], post_id), one=True)
    
    if liked:
        execute('DELETE FROM post_likes WHERE user_id=%s AND post_id=%s', (user['id'], post_id))
        execute('UPDATE posts SET likes = GREATEST(0, CAST(likes AS SIGNED) - 1) WHERE id=%s', (post_id,))
        is_liked = False
    else:
        execute('INSERT IGNORE INTO post_likes (user_id, post_id) VALUES (%s, %s)', (user['id'], post_id))
        execute('UPDATE posts SET likes = likes + 1 WHERE id=%s', (post_id,))
        is_liked = True
        
    new_count = query('SELECT likes FROM posts WHERE id=%s', (post_id,), one=True)
    return jsonify({'status': 'success', 'is_liked': is_liked, 'likes_count': new_count['likes'] if new_count else 0})


@app.route('/api/post/comment/<int:post_id>', methods=['POST'])
@login_required
def api_comment_post(user, post_id):
    user = normalise_user(user)
    content = request.json.get('content', '').strip()
    if not content: return jsonify({'status': 'error', 'message': 'Comment cannot be empty'}), 400
    
    res = execute('INSERT INTO post_comments (post_id, user_id, content) VALUES (%s, %s, %s)', (post_id, user['id'], content))
    if res > 0:
        execute('UPDATE posts SET comments = comments + 1 WHERE id=%s', (post_id,))
        return jsonify({'status': 'success', 'comment': {'author_name': user['full_name'], 'avatar_url': user['avatar_url'], 'content': content}})
    return jsonify({'status': 'error', 'message': 'Database error'}), 500


@app.route('/api/post/delete/<int:post_id>', methods=['POST'])
@login_required
def api_delete_post(user, post_id):
    """Delete a post (author only)."""
    user = normalise_user(user)
    rows = query('SELECT user_id FROM posts WHERE id=%s', (post_id,))
    if not rows:
        return jsonify({'status': 'error', 'message': 'Post not found'}), 404
    if rows[0]['user_id'] != user['id']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    execute('DELETE FROM posts WHERE id=%s', (post_id,))
    return jsonify({'status': 'success'})


@app.route('/api/post/report/<int:post_id>', methods=['POST'])
@login_required
def api_report_post(user, post_id):
    """Report an inappropriate post."""
    user = normalise_user(user)
    data = request.json or {}
    reason = data.get('reason', 'Unspecified post misconduct').strip()

    try:
        execute(
            'INSERT INTO reports (reporter_id, target_id, reason) VALUES (%s, %s, %s)',
            (user['id'], -post_id, f"POST_REPORT: {reason}")
        )
    except:
        pass

    return jsonify({'status': 'success', 'message': 'Post report submitted.'})


@app.route("/api/report/<int:other_id>", methods=["POST"])
@login_required
def api_report_user(user, other_id):
    """Report a user for misconduct."""
    user = normalise_user(user)
    data = request.json or {}
    reason = data.get('reason', 'No specific reason given.').strip()

    try:
        execute(
            'INSERT INTO reports (reporter_id, target_id, reason) VALUES (%s, %s, %s)',
            (user['id'], other_id, reason)
        )
        print(f"[REPORT] User {user['id']} reported {other_id} for: {reason}")
        return jsonify({'status': 'success', 'message': 'User reported.'})
    except Exception as e:
        print(f"[REPORT ERROR] {e}")
        return jsonify({'status': 'success', 'message': 'Report submitted for review.'})


@app.route("/api/messages/<int:other_id>", methods=["GET"])
@login_required
def api_get_messages(user, other_id):
    """Fetch chat history with a specific user."""
    user = normalise_user(user)
    rows = query(
        '''SELECT id, sender_id, content, media_url, created_at
           FROM messages
           WHERE (sender_id=%s AND receiver_id=%s)
              OR (sender_id=%s AND receiver_id=%s)
           ORDER BY created_at ASC
           LIMIT 50''',
        (user['id'], other_id, other_id, user['id'])
    )
    return jsonify({'status': 'success', 'messages': rows if rows else []})


@app.route("/api/messages/send", methods=["POST"])
@login_required
def api_send_message(user):
    """Send a private message."""
    user = normalise_user(user)

    # Can be multipart (with file) or json
    if request.is_json:
        data = request.json or {}
        receiver_id = data.get('receiver_id')
        content = data.get('content', '').strip()
        media_file = None
        print(f"[CHAT] Received JSON message: {content} to user {receiver_id}")
    else:
        receiver_id = request.form.get('receiver_id')
        content = request.form.get('content', '').strip()
        media_file = request.files.get('file')
        print(f"[CHAT] Received Form message: {content} to user {receiver_id}, media: {media_file.filename if media_file else 'None'}")

    if not receiver_id or (not content and not media_file):
        return jsonify({'status': 'error', 'message': 'Missing recipient or content'}), 400

    media_url = None
    if media_file:
        try:
            ext = 'jpg'
            if '.' in media_file.filename:
                ext = media_file.filename.rsplit('.', 1)[1].lower()
            fname = f"msg_{user['id']}_{int(time.time())}.{ext}"
            save_path = os.path.join(MSG_UPLOAD_FOLDER, fname)
            media_file.save(save_path)
            media_url = f"/static/uploads/messages/{fname}"
            print(f"[CHAT] Media saved: {media_url}")
        except Exception as e:
            print(f"[CHAT ERROR] File upload failed: {e}")
            return jsonify({'status': 'error', 'message': f'File upload failed: {e}'}), 500

    try:
        # Convert receiver_id to int to be safe
        rid = int(receiver_id)
        res = execute(
            'INSERT INTO messages (sender_id, receiver_id, content, media_url) VALUES (%s, %s, %s, %s)',
            (user['id'], rid, content, media_url)
        )
        if res > 0:
            return jsonify({'status': 'success', 'message_id': res, 'media_url': media_url})
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[CHAT ERROR] DB Insert failed: {e}")
        return jsonify({'status': 'error', 'message': f'Insert failed: {e}'}), 500


@app.route("/network")
@login_required
def network(user):
    user = normalise_user(user)
    # 1. Fetch accepted connections
    conn_rows = query(
        """SELECT u.id, u.full_name AS name, u.title, u.avatar_url
           FROM connections c
           JOIN users u ON (
               CASE WHEN c.requester_id=%s THEN c.receiver_id ELSE c.requester_id END = u.id
           )
           WHERE (c.requester_id=%s OR c.receiver_id=%s) AND c.status='accepted'
           LIMIT 30""",
        (user["id"], user["id"], user["id"]),
    )
    friends = conn_rows if conn_rows else (DEMO_FRIENDS if user['id'] == 0 else [])
    
    # 2. Fetch suggestions (users not connected)
    sug_rows = query(
        '''SELECT id, full_name AS name, title, avatar_url 
           FROM users 
           WHERE id != %s AND id NOT IN (
               SELECT CASE WHEN requester_id=%s THEN receiver_id ELSE requester_id END
               FROM connections 
               WHERE requester_id=%s OR receiver_id=%s
           )
           LIMIT 5''',
        (user['id'], user['id'], user['id'], user['id'])
    )
    suggestions = sug_rows if sug_rows else (DEMO_SUGGESTIONS if user['id'] == 0 else [])
    
    for f in (friends + suggestions):
        # Ensure name exists for first-letter fallback
        display_name = (f.get('name') or f.get('username') or 'User')
        if not f.get('avatar_url'):
            initial = display_name[0] if display_name else 'U'
            f['avatar_url'] = f"https://ui-avatars.com/api/?name={initial}&background=random&rounded=true"
            
    return render_template('network.html', user=user, friends=friends, suggestions=suggestions)


@app.route('/api/connect/<int:target_id>', methods=['POST'])
@login_required
def api_connect(user, target_id):
    user = normalise_user(user)
    
    # 1. Prevent connecting to self
    if user['id'] == target_id:
        return jsonify({'status': 'error', 'message': 'Cannot connect to yourself'}), 400
    
    # 2. Check if connection already exists
    existing = query(
        'SELECT id FROM connections WHERE (requester_id=%s AND receiver_id=%s) OR (requester_id=%s AND receiver_id=%s)',
        (user['id'], target_id, target_id, user['id']),
        one=True
    )
    if existing:
        return jsonify({'status': 'error', 'message': 'Connection already exists or is pending'}), 400
    
    # 3. Create connection (auto-accepted for demo purposes)
    res = execute(
        'INSERT INTO connections (requester_id, receiver_id, status) VALUES (%s, %s, "accepted")',
        (user['id'], target_id)
    )
    
    if res > 0:
        return jsonify({'status': 'success', 'message': 'Successfully connected!'})
    elif res == -2:
        return jsonify({'status': 'error', 'message': 'Connection already exists'}), 400
    else:
        return jsonify({'status': 'error', 'message': 'Database error. Ensure you have the local MySQL running.'}), 500


@app.route('/api/disconnect/<int:target_id>', methods=['POST'])
@login_required
def api_disconnect(user, target_id):
    user = normalise_user(user)
    
    # Delete where either user is the requester and the other is receiver
    res = execute(
        '''DELETE FROM connections 
           WHERE (requester_id=%s AND receiver_id=%s) 
              OR (requester_id=%s AND receiver_id=%s)''',
        (user['id'], target_id, target_id, user['id'])
    )
    
    if res >= 0:
        return jsonify({'status': 'success', 'message': 'Connection removed.'})
    return jsonify({'status': 'error', 'message': 'Database error'}), 500


@app.route("/market")
@login_required
def market(user):
    user = normalise_user(user)
    
    # Fetch active listings from DB
    listings = query("""
        SELECT l.*, u.full_name AS seller_name, u.location AS seller_location
        FROM market_listings l
        JOIN users u ON l.seller_id = u.id
        WHERE l.status = 'active'
        ORDER BY l.created_at DESC
    """)
    
    # Map demo catalog to auto-heal seed data lacking images
    demo_catalog = {d['title']: d for d in DEMO_LISTINGS}
    for l in listings:
        if not l.get('image_url') and l['title'] in demo_catalog:
            l['image_url'] = demo_catalog[l['title']]['image_url']
        if not l.get('description') and l['title'] in demo_catalog:
            l['description'] = demo_catalog[l['title']]['description']

    # Combine real listings with remaining demo data for full UI
    existing_titles = {l['title'] for l in listings}
    unique_demos = [d for d in DEMO_LISTINGS if d['title'] not in existing_titles]
    
    all_items = listings + unique_demos
    
    return render_template("market.html", user=user, listings=all_items)


@app.route("/api/market/create", methods=["POST"])
@login_required
def api_create_listing(user):
    user = normalise_user(user)
    
    category = request.form.get("category")
    listing_type = request.form.get("listing_type")
    title = request.form.get("title")
    price = request.form.get("price")
    price_unit = request.form.get("price_unit", "")
    description = request.form.get("description", "")
    contact_phone = request.form.get("contact_phone", "")
    image = request.files.get("image")

    if not all([category, listing_type, title, price]):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    image_url = ""
    if image and image.filename:
        filename = f"{uuid.uuid4()}_{image.filename}"
        save_path = os.path.join(MARKET_UPLOAD_FOLDER, filename)
        image.save(save_path)
        image_url = f"/static/uploads/market/{filename}"

    res = execute(
        """INSERT INTO market_listings 
           (seller_id, title, description, category, listing_type, price, price_unit, image_url, location, contact_phone)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (user['id'], title, description, category, listing_type, price, price_unit, image_url, user['location'], contact_phone)
    )

    if res > 0:
        return jsonify({"status": "success", "message": "Listing created", "listing_id": res})
    return jsonify({"status": "error", "message": "Database error"}), 500


@app.route("/api/market/book/<int:listing_id>", methods=["POST"])
@login_required
def api_book_listing(user, listing_id):
    user = normalise_user(user)

    listing = query("SELECT seller_id, title FROM market_listings WHERE id=%s", (listing_id,), one=True)
    if not listing:
        return jsonify({"status": "error", "message": "Listing not found"}), 404
        
    if listing['seller_id'] == user['id']:
        return jsonify({"status": "error", "message": "You cannot book your own listing"}), 400

    # Ensure not already booked pending
    existing = query("SELECT id FROM market_bookings WHERE buyer_id=%s AND listing_id=%s AND status='pending'", 
                     (user['id'], listing_id), one=True)
    if existing:
        return jsonify({"status": "error", "message": "You already have a pending request for this item"}), 400

    res = execute(
        "INSERT INTO market_bookings (buyer_id, seller_id, listing_id) VALUES (%s, %s, %s)",
        (user['id'], listing['seller_id'], listing_id)
    )

    if res > 0:
        return jsonify({"status": "success", "message": f"Successfully requested {listing['title']}!"})
    return jsonify({"status": "error", "message": "Database error"}), 500


@app.route("/api/market/booking/<int:booking_id>/<action>", methods=["POST"])
@login_required
def api_update_booking(user, booking_id, action):
    user = normalise_user(user)
    
    if action not in ['accept', 'reject']:
        return jsonify({"status": "error", "message": "Invalid action"}), 400

    booking = query("SELECT seller_id FROM market_bookings WHERE id=%s", (booking_id,), one=True)
    if not booking or booking['seller_id'] != user['id']:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    status_str = "accepted" if action == "accept" else "rejected"
    res = execute("UPDATE market_bookings SET status=%s WHERE id=%s", (status_str, booking_id))
    
    if res >= 0:
        return jsonify({"status": "success", "message": f"Booking {status_str}."})
    return jsonify({"status": "error", "message": "Database error"}), 500


@app.route("/inbox")
@login_required
def inbox(user):
    user = normalise_user(user)
    
    # Received requests (User is seller)
    received = query("""
        SELECT b.id, b.status, b.created_at, 
               l.title AS item_title, l.price, l.price_unit, l.image_url,
               u.full_name AS buyer_name, u.location AS buyer_location
        FROM market_bookings b
        JOIN market_listings l ON b.listing_id = l.id
        JOIN users u ON b.buyer_id = u.id
        WHERE b.seller_id = %s
        ORDER BY b.created_at DESC
    """, (user['id'],))
    
    # Sent requests (User is buyer)
    sent = query("""
        SELECT b.id, b.status, b.created_at, 
               l.title AS item_title, l.price, l.price_unit, l.image_url, l.contact_phone,
               u.full_name AS seller_name
        FROM market_bookings b
        JOIN market_listings l ON b.listing_id = l.id
        JOIN users u ON b.seller_id = u.id
        WHERE b.buyer_id = %s
        ORDER BY b.created_at DESC
    """, (user['id'],))

    return render_template("inbox.html", user=user, received=received, sent=sent)


@app.route("/profile/<int:user_id>")
@login_required
def profile_page(user, user_id):
    user = normalise_user(user)
    
    # 1. Fetch targeted user
    target = query("SELECT * FROM users WHERE id=%s", (user_id,), one=True)
    if not target:
        return redirect("/") # Or a 404 page
        
    target = normalise_user(target)
    
    # 2. Check connection status
    conn = query(
        "SELECT status FROM connections WHERE (requester_id=%s AND receiver_id=%s) OR (requester_id=%s AND receiver_id=%s)",
        (user['id'], user_id, user_id, user['id']),
        one=True
    )
    is_connected = conn['status'] == 'accepted' if conn else False
    is_pending = conn['status'] == 'pending' if conn else False
    
    # 3. Fetch user's posts
    posts = query("""
        SELECT p.*, u.full_name AS author_name, u.avatar_url 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = %s
        ORDER BY p.created_at DESC
    """, (user_id,))
    
    return render_template("profile.html", user=user, target=target, posts=posts, is_connected=is_connected, is_pending=is_pending)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

