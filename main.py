import os
import json
import secrets
import time
import asyncio
import logging
import sqlite3
import shutil
import pyotp
import httpx
import redis
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from collections import defaultdict

# --- FastAPI and Starlette Imports ---
from fastapi import FastAPI, Depends, HTTPException, Request, Header, Form, status, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import StreamingResponse
from pydantic import BaseModel

# --- SQLAlchemy and MySQL Imports (from server-release.py) ---
from sqlalchemy import create_engine, Column, Integer, String, text, DateTime
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from mysql.connector import Error as MySQLError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# =========================================================================
# ⚙️ CONFIGURATION (IMPORTANT: Set these as environment variables)
# =========================================================================

# Helper for required integer environment variables
def get_required_int(key):
    val = os.environ.get(key)
    if val is None:
        raise ValueError(f"FATAL: Required environment variable '{key}' is not set.")
    try:
        return int(val)
    except ValueError:
        raise ValueError(f"FATAL: Environment variable '{key}' must be an integer.")

# Helper for required string environment variables
def get_required_str(key):
    val = os.environ.get(key)
    if not val:
        raise ValueError(f"FATAL: Required environment variable '{key}' is not set or is empty.")
    return val

# Core API Config
DATABASE_URL = get_required_str("DATABASE_URL")
TOKEN_VALIDITY_SECONDS = get_required_int("TOKEN_VALIDITY_SECONDS")
CLEANUP_INTERVAL_MINUTES = get_required_int("CLEANUP_INTERVAL_MINUTES")
SECRET_KEY = get_required_str("SECRET_KEY")
XENFORO_API_URL = get_required_str("XENFORO_API_URL")
XENFORO_API_KEY = get_required_str("XENFORO_API_KEY")

# 🌟 FIX: The download path is now configurable via an environment variable for consistency with Docker setup.
# The default value is a fallback for local development without Docker.
DOWNLOAD_FILE_PATH = os.environ.get("DOWNLOAD_FILE_PATH", "./Loader/client.exe")

# Admin key for the secure loader upload endpoint. Set this in Dokploy env vars.
LOADER_UPLOAD_KEY = os.environ.get("LOADER_UPLOAD_KEY", "")

# 🌟 FIX: Point to the database file inside the mounted data volume for robustness.
LOG_DATABASE_FILE = '/main-server/data/logs.db'

TOTP_SECRET = get_required_str("LOGGER_TOTP_SECRET") 
ACTIVITY_TIMEOUT_SECONDS = 30 # This is a reasonable default and can remain constant

# Logging API Key
LOGGING_API_KEY = get_required_str("LOGGING_API_KEY")

# Rate Limiting
RATE_LIMIT_REQUESTS = get_required_int("RATE_LIMIT_REQUESTS")
RATE_LIMIT_WINDOW = get_required_int("RATE_LIMIT_WINDOW")

# Redis Config
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
LOG_CHANNEL = "log_stream"

# =========================================================================
# 💾 DATABASE SETUP (MySQL for Tokens)
# =========================================================================

engine = create_engine(DATABASE_URL)
Base = declarative_base()

# Define the Token model (as in server-release.py)
class Token(Base):
    __tablename__ = "tokens"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    value = Column(String(255), unique=True, index=True)
    timestamp = Column(Integer)
    username = Column(String(255))
    hwid = Column(String(255))
    user_id = Column(String(255))
    user_photo_url = Column(String(512))

# Create tables in MySQL if they don't exist
try:
    Base.metadata.create_all(bind=engine)
except MySQLError as e:
    logger.error(f"Failed to connect to MySQL or create tables: {e}")
    # Application will likely fail at runtime if DB connection is truly down

# Dependency for MySQL (Tokens)
def get_db():
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    try:
        yield db
    except (SQLAlchemyError, MySQLError) as e:
        logger.error(f"Failed to get MySQL session: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to establish database connection")
    finally:
        try:
            db.close()
        except Exception as e:
            logger.warning(f"Error closing MySQL session: {e}")

# =========================================================================
# 💾 DATABASE SETUP (SQLite for Logs)
# =========================================================================

def init_log_db():
    """Initializes the SQLite database for logs."""
    conn = sqlite3.connect(LOG_DATABASE_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            method TEXT,
            path TEXT,
            headers TEXT,
            remote_addr TEXT,
            
            user_id TEXT,
            username TEXT,
            user_photo_url TEXT,
            profile_url TEXT,
            hardware_id TEXT,
            log_level TEXT,
            log_title TEXT,
            log_message TEXT,
            raw_body TEXT
        )
    ''')
    conn.commit()
    conn.close()

print("Initializing database...")
init_log_db()

def create_logs_table():
    """Ensures the SQLite logs table exists. Must be called on startup."""
    try:
        conn = sqlite3.connect(LOG_DATABASE_FILE)
        c = conn.cursor()
        
        # NOTE: This SQL schema assumes the full set of log fields used in your /log endpoint
        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                log_level TEXT,
                log_title TEXT,
                log_message TEXT,
                user_id TEXT,
                username TEXT,
                hardware_id TEXT,
                user_photo_url TEXT,
                method TEXT,
                path TEXT,
                headers TEXT,
                remote_addr TEXT,
                raw_body TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        # Crucial to catch errors here, especially if the path is bad
        print(f"FATAL ERROR: Could not create logs table in {LOG_DATABASE_FILE}. Error: {e}")
        
print("Ensuring logs table exists...")
create_logs_table()
# =========================================================================
# 🧩 GLOBAL STATE & HELPERS
# =========================================================================

# 🌟 PRODUCTION REFACTOR: Use a native async Redis client and centralize rate-limiting.
class RedisManager:
    def __init__(self, url: str):
        # Use the async-native client from redis-py
        self.client = redis.asyncio.from_url(url, decode_responses=True)

    async def check_connection(self):
        """Verifies connection to Redis on startup."""
        try:
            await self.client.ping()
            logger.info("Successfully connected to Redis.")
        except redis.exceptions.ConnectionError as e:
            logger.error(f"FATAL: Could not connect to Redis at {REDIS_URL}. Please ensure it is running. Error: {e}")
            raise e

    # --- Session Management ---
    async def set_session(self, session_id: str, expiry_minutes: int) -> None:
        """Stores a session ID in Redis with an expiration."""
        await self.client.set(f"session:{session_id}", "1", ex=expiry_minutes * 60)

    async def get_session(self, session_id: str) -> bool:
        """Checks if a session ID exists and renews it if it does."""
        # Using a pipeline ensures atomicity and is more efficient.
        async with self.client.pipeline() as pipe:
            pipe.get(f"session:{session_id}")
            pipe.expire(f"session:{session_id}", SESSION_TIMEOUT_MINUTES * 60)
            results = await pipe.execute()
            return results[0] is not None

    async def delete_session(self, session_id: str) -> None:
        """Deletes a session from Redis."""
        await self.client.delete(f"session:{session_id}")

    # --- Active User Tracking ---
    async def update_active_user(self, user_id: str, user_data: Dict[str, Any]) -> None:
        """Stores active user data as a hash in Redis."""
        # Use a pipeline for atomic set and expire operations.
        async with self.client.pipeline() as pipe:
            pipe.hset(f"active_user:{user_id}", mapping=user_data)
            pipe.expire(f"active_user:{user_id}", ACTIVITY_TIMEOUT_SECONDS + 10) # Give a small buffer
            await pipe.execute()

    async def get_active_users(self) -> List[Dict[str, Any]]:
        """Efficiently retrieves all active user hashes from Redis using SCAN and a pipeline."""
        user_keys = [key async for key in self.client.scan_iter("active_user:*")]
        if not user_keys:
            return []
        
        async with self.client.pipeline() as pipe:
            for key in user_keys:
                pipe.hgetall(key)
            return await pipe.execute()

    # --- Rate Limiting ---
    async def check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Checks and enforces a rate limit for a given key. Returns True if limit is exceeded."""
        current_time = time.time()
        async with self.client.pipeline() as pipe:
            # Atomically remove old entries and add the new one
            pipe.zremrangebyscore(key, 0, current_time - window)
            pipe.zadd(key, {str(current_time): current_time})
            pipe.zcard(key)
            pipe.expire(key, window) # Ensure the key eventually expires
            results = await pipe.execute()
            return results[2] > limit

    # --- Pub/Sub for Real-Time Logs ---
    async def publish_log(self, channel: str, log_data: Dict[str, Any]):
        """Publishes a log message to a Redis channel."""
        await self.client.publish(channel, json.dumps(log_data))

    async def subscribe_to_logs(self, channel: str):
        """Subscribes to a log channel and yields messages."""
        async with self.client.pubsub() as pubsub:
            await pubsub.subscribe(channel)
            while True:
                # Wait for a message with a timeout to allow checking for disconnects
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get('type') == 'message':
                    yield message.get('data')

redis_manager = RedisManager(REDIS_URL)

# Token Rate Limiting (from server-release.py)
rate_limit_data = defaultdict(list)

# 🌟 SECURITY FIX: Add a separate rate limiter for login attempts
# Session constants (30 days = 43200 minutes)
SESSION_TIMEOUT_MINUTES = 43200
SESSION_COOKIE_NAME = "X-Session-ID"

def format_iso_timestamp(iso_str):
    """Converts ISO format string to a human-readable local time string."""
    try:
        dt_utc = datetime.fromisoformat(iso_str)
        if dt_utc.tzinfo is None or dt_utc.tzinfo.utcoffset(dt_utc) is None:
            dt_utc = dt_utc.replace(tzinfo=timezone.utc)
        dt_local = dt_utc.astimezone()
        return dt_local.strftime('%b %d, %Y | %I:%M:%S %p')
    except ValueError:
        return iso_str

def get_logs(filter_text: str, level_filter: str = '', page: int = 1, page_size: int = 100):
    """Fetches a paginated list of logs from the SQLite database."""
    # Limit filter text length to prevent DoS via long queries.
    if len(filter_text) > 100:
        filter_text = filter_text[:100]
    if len(level_filter) > 20:
        level_filter = ''

    conn = sqlite3.connect(LOG_DATABASE_FILE)
    
    try:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        if not c.fetchone():
            return [], 0

        offset = (page - 1) * page_size
        conditions = []
        params: list = []

        # Server-side text search across key columns
        if filter_text:
            filter_pattern = f'%{filter_text}%'
            text_conditions = (
                "(log_title LIKE ? OR log_message LIKE ? OR username LIKE ? "
                "OR remote_addr LIKE ? OR hardware_id LIKE ? OR user_id LIKE ?)"
            )
            conditions.append(text_conditions)
            params.extend([filter_pattern] * 6)

        # Server-side level filter
        if level_filter:
            conditions.append("LOWER(log_level) = ?")
            params.append(level_filter.lower())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        count_query = f"SELECT COUNT(*) FROM logs {where_clause}"
        total_logs = c.execute(count_query, params).fetchone()[0]
        total_pages = max(1, (total_logs + page_size - 1) // page_size)

        data_query = f"SELECT * FROM logs {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
        c.execute(data_query, params + [page_size, offset])
        logs = c.fetchall()

        return logs, total_pages
        
    finally:
        conn.close()

async def update_active_user(user_id: str, username: str, photo_url: str):
    """
    Core logic: Updates the in-memory active user tracker, now with first_seen timestamp.
    This function is called upon successful /api/token/generate and /log calls.
    """
    # Use the static path if photo URL is not provided
    if not photo_url or photo_url == "https://supreme-cheats.xyz/anonymus.png":
        photo_url = "/static/default-user.png"

    # Profile URL placeholder based on the username
    profile_url = f"https://supreme-cheats.xyz/forum/index.php?members/{user_id}"
    
    now_iso = datetime.now(timezone.utc).isoformat()
    
    # Check for existing data to preserve the first_seen timestamp
    existing_data = await redis_manager.client.hgetall(f"active_user:{user_id}")
    
    # If 'first_seen' isn't in existing_data, it's a new session, so use the current time.
    first_seen = existing_data.get('first_seen', now_iso)

    user_data = {
        'username': username, 
        'photo_url': photo_url, 
        'profile_url': profile_url, 
        'last_seen': now_iso,
        'first_seen': first_seen  # Add or preserve the first_seen timestamp
    }
    
    await redis_manager.update_active_user(user_id, user_data)
    logger.info(f"Active user updated: {username} ({user_id})")

# =========================================================================
# 💻 FASTAPI APPLICATION SETUP
# =========================================================================

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# Mount Static Files and Templates for Dashboard
# NOTE: Assumes the logger-server.zip contents are extracted into the same directory structure
app.mount("/static", StaticFiles(directory="logger-server/static"), name="static")
templates = Jinja2Templates(directory="logger-server/templates")
templates.env.filters['format_time'] = format_iso_timestamp

# =========================================================================
# 🛡️ SECURITY HEADERS MIDDLEWARE
# =========================================================================

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Global rate limiting middleware based on IP address."""
    # This middleware runs after the proxy_headers_middleware, so request.client.host is correct.
    if request.url.path.startswith("/api"):
        client_ip = request.client.host
        rate_limit_key = f"rate_limit:{client_ip}"
        
        if await redis_manager.check_rate_limit(rate_limit_key, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW):
            logger.warning(f"Rate limit exceeded for IP: {client_ip} on API endpoint.")
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Please try again later."})
        
    response = await call_next(request)
    return response

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Adds essential security headers to all responses."""
    response = await call_next(request)
    
    response.headers["X-Frame-Options"] = "DENY" 
    
    response.headers["X-Content-Type-Options"] = "nosniff" 

    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: https://supreme-cheats.xyz;"
    
    return response

# 🌟 FIX: This middleware is defined last, so it runs FIRST.
# It corrects the client IP before any other middleware (like rate limiting) sees it.
@app.middleware("http")
async def proxy_headers_middleware(request: Request, call_next):
    """
    Parses X-Forwarded-For headers to get the real client IP
    when running behind a reverse proxy.
    """
    # The X-Forwarded-For header can contain a comma-separated list of IPs.
    # The original client IP is typically the first one in the list.
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP from the list and strip any whitespace
        client_ip = forwarded_for.split(",")[0].strip()
        # Update the request's scope to reflect the real client IP.
        # This makes `request.client.host` return the correct IP downstream
        # for all other middleware and route handlers.
        request.scope["client"] = (client_ip, request.scope["client"][1])

    response = await call_next(request)
    return response


# =========================================================================
# 🛡️ MIDDLEWARES AND DEPENDENCIES
# =========================================================================

async def verify_api_secret_key(secret_key: str = Header(..., alias="X-Secret-Key")):
    """Dependency to verify the main API key (for loader endpoints)."""
    if secret_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid secret key")
    return secret_key

# Dependency for HTML pages (forces browser redirect)
async def require_dashboard_session_html(request: Request, response: JSONResponse) -> str:
    """Dependency for HTML pages: checks session and forces redirect to /login on failure."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    
    # 🌟 FIX: Check session in Redis. The `get_session` method also renews the TTL.
    if session_id and await redis_manager.get_session(session_id):
        # 🌟 FIX: Renew the cookie's max_age in the browser on every HTML page load
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_id,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=SESSION_TIMEOUT_MINUTES * 60
        )
        return session_id
    
    # If not authenticated, redirect to login (Browser follows this 303)
    # Raising an exception with a redirection status code is how FastAPI/Starlette handles redirects in dependencies.
    raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, detail="Not authenticated", headers={"Location": "/logs/login"})

# Dependency for API/AJAX endpoints (returns JSON 401)
async def require_dashboard_session_api(request: Request) -> str:
    """Dependency for API/AJAX calls: checks session and returns 401 on failure."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    
    # 🌟 FIX: Check session in Redis. The `get_session` method also renews the TTL.
    if session_id and await redis_manager.get_session(session_id):
        return session_id
    
    # Return 401 for AJAX/API to prevent browser from loading HTML
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired. Please log in.")


class TokenRequest(BaseModel):
    username: str
    password: str
    hwid: str

class VerificationRequest(BaseModel):
    token: str

class LogEntryData(BaseModel):
    user_id: str
    username: str
    user_photo_url: Optional[str] = None
    profile_url: Optional[str] = None
    hardware_id: Optional[str] = None
    log_level: str
    log_title: str
    log_message: str


async def authenticate_xenforo(username, password):
    """Authenticates against the Xenforo REST API."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{XENFORO_API_URL}/api/auth/",
                headers={"XF-Api-Key": XENFORO_API_KEY},
                data={"login": username, "password": password},
                timeout=10
            )
            data = response.json()
            if data.get("success"):
                avatar_url = data.get("user", {}).get("avatar_urls", {}).get("o") or "https://supreme-cheats.xyz/anonymus.png"
                is_customer = 5 in data.get("user", {}).get("secondary_group_ids", [])
                if not avatar_url:
                    avatar_url = data.get("avatar_url") or "https://supreme-cheats.xyz/anonymus.png"
                
                return {
                    "success": True,
                    "avatar_url": avatar_url,
                    "is_customer": is_customer,
                    "user_id": data.get("user", {}).get("user_id") # Ensure user_id is returned
                }
            else:
                logger.info(data)
                logger.error(f"Xenforo authentication failed: {data['errors'][0]['code']}")
                return {"success": False, "avatar_url": "", "error": data['errors'][0]['code']}
            
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during Xenforo authentication: {e}")
            return {"success": False, "error": str(e)}
        except httpx.RequestError as e:
            logger.error(f"Request error during Xenforo authentication: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error during Xenforo authentication: {e}")
            return {"success": False, "error": str(e)}
        
def check_and_set_hwid(username: str, hwid: str, db: Session) -> bool:
    try:
        query = text("""
            SELECT hwid 
            FROM xf_user 
            WHERE username = :username 
            LIMIT 1
        """)
        result = db.execute(query, {"username": username}).fetchone()
        
        # 🌟 ROBUSTNESS FIX: Check if a result was returned before accessing it.
        if result and result[0] is not None:
            if result[0] == hwid:
                return True
            else:
                logger.error(f"Wrong hwid for user {username} detected.")
                return False
        elif result: # Result was found, but HWID is NULL
            setquery = text("""
            UPDATE xf_user
            SET hwid = :hwid
            WHERE username = :username 
            """)
            update_result = db.execute(setquery, {"hwid": hwid, "username": username})
            db.commit()
    
            if update_result.rowcount > 0:
                logger.info(f"New hwid for user {username} has been set.")
                return True
            else:
                logger.error(f"Failed to set hwid for user {username}.")
                return False
        else: # No user found with that username
            logger.error(f"Attempted to check/set HWID for non-existent user: {username}")
            return False
                
    except SQLAlchemyError as e:
        logger.error(f"Database error getting hwid: {e}")
        raise HTTPException(status_code=500, detail="Database error")


def verify_token_function(token: str, db: Session) -> Optional[Token]:
    """Placeholder for token verification logic."""
    
    # Check if a token matching the value (or part of it) exists and is not expired
    db_token = db.query(Token).filter(Token.value == token).first()
    
    if db_token:
        expiration_time = db_token.timestamp + TOKEN_VALIDITY_SECONDS
        if time.time() <= expiration_time:
            return db_token
        else:
            db.delete(db_token)
            db.commit()
            return None
    return None

# =========================================================================
# 💓 HEALTH CHECK & ADMIN ENDPOINTS
# =========================================================================

@app.get("/health")
async def health_check():
    """Lightweight health check endpoint for Dokploy container monitoring.
    Checks Redis and MySQL connectivity without requiring auth.
    """
    health = {"status": "ok", "services": {}}

    # Check Redis
    try:
        await redis_manager.client.ping()
        health["services"]["redis"] = "ok"
    except Exception as e:
        health["services"]["redis"] = f"error: {str(e)}"
        health["status"] = "degraded"

    # Check MySQL
    try:
        db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
        db.execute(text("SELECT 1"))
        db.close()
        health["services"]["mysql"] = "ok"
    except Exception as e:
        health["services"]["mysql"] = f"error: {str(e)}"
        health["status"] = "degraded"

    status_code = 200 if health["status"] == "ok" else 503
    return JSONResponse(content=health, status_code=status_code)


@app.post("/api/admin/upload-loader")
async def upload_loader(
    file: UploadFile = File(...),
    x_loader_key: str = Header(..., alias="X-Loader-Key")
):
    """Securely update client.exe on the server without redeploying.
    Protected by X-Loader-Key header matching the LOADER_UPLOAD_KEY env var.
    
    Usage:
        curl -X POST https://cloud.supreme-cheats.xyz/api/admin/upload-loader \
          -H "X-Loader-Key: your_secret_key" \
          -F "file=@client.exe"
    """
    if not LOADER_UPLOAD_KEY:
        raise HTTPException(status_code=503, detail="Upload endpoint not configured. Set LOADER_UPLOAD_KEY env var.")
    if x_loader_key != LOADER_UPLOAD_KEY:
        raise HTTPException(status_code=403, detail="Invalid upload key")
    if not file.filename or not file.filename.lower().endswith('.exe'):
        raise HTTPException(status_code=400, detail="Only .exe files are accepted")

    loader_dir = os.path.dirname(DOWNLOAD_FILE_PATH)
    os.makedirs(loader_dir, exist_ok=True)

    # Write atomically: save to temp file first, then replace
    temp_path = DOWNLOAD_FILE_PATH + ".tmp"
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        os.replace(temp_path, DOWNLOAD_FILE_PATH)
    finally:
        file.file.close()
        if os.path.exists(temp_path):
            os.remove(temp_path)

    logger.info(f"✅ Loader updated successfully: {DOWNLOAD_FILE_PATH} (uploaded: {file.filename})")
    return {
        "success": True,
        "message": "Loader updated successfully",
        "filename": file.filename
    }


# =========================================================================
# 🚀 API ENDPOINTS (Loader/Token Logic)
# =========================================================================

@app.post("/api/token/generate")
async def create_token(request: TokenRequest, db: Session = Depends(get_db), secret_key: str = Depends(verify_api_secret_key)):
    """
    Generates a new token if authentication and subscription checks pass.
    MODIFIED: Updates the active user tracker on success.
    """
    try:
        auth_result = await authenticate_xenforo(request.username, request.password)
        
        if not auth_result["success"]:
            raise HTTPException(status_code=401, detail=auth_result["error"])
        
        user_id = str(auth_result.get("user_id", request.username))
        avatar_url = auth_result.get("avatar_url", "https://supreme-cheats.xyz/anonymus.png")
        is_customer = auth_result.get("is_customer", False)
        
        is_hwid_valid = check_and_set_hwid(request.username, request.hwid, db)
        if not is_hwid_valid:
            raise HTTPException(status_code=403, detail={"detail": "HWID mismatch, please contact support", "user_id": user_id, "avatar_url": avatar_url})
        
        if not is_customer:
            raise HTTPException(status_code=401, detail={"detail": "No subscription found", "user_id": user_id, "avatar_url": avatar_url})
        
        # Check for existing valid token
        # The token value is generated with a safe part + the HWID
        token_safe_part = secrets.token_urlsafe(32)
        concatenated_token = token_safe_part + request.hwid
        
        existing_token = db.query(Token).filter(Token.username == request.username).first()

        if existing_token:
            expiration_time = existing_token.timestamp + TOKEN_VALIDITY_SECONDS
            if time.time() <= expiration_time:
                
                # --- ACTIVE USER UPDATE (EXISTING TOKEN) ---
                await update_active_user(user_id, request.username, avatar_url)
                # -------------------------------------------
                
                return {"token": existing_token.value, "timestamp": existing_token.timestamp, "avatar_url": avatar_url, "user_id": user_id}
            else:
                db.delete(existing_token)
                db.commit()

        timestamp = int(time.time())
        db_token = Token(
            value=concatenated_token, 
            username=request.username, 
            hwid=request.hwid, 
            timestamp=timestamp,
            user_id=user_id,
            user_photo_url=avatar_url
        )
        db.add(db_token)
        db.commit()
        db.refresh(db_token)
        
        # --- ACTIVE USER UPDATE (NEW TOKEN) ---
        await update_active_user(user_id, request.username, avatar_url)
        # --------------------------------------
        
        return {"token": db_token.value, "timestamp": db_token.timestamp, "avatar_url": avatar_url, "user_id": user_id}
        
    except HTTPException as http_ex:
        db.rollback()
        raise http_ex
    except Exception as e:
        logger.error(f"Error creating token: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create token")

@app.post("/api/token/verify")

async def verify_token(
    request: VerificationRequest, 
    db: Session = Depends(get_db), 
    secret_key: str = Depends(verify_api_secret_key)
):
    """
    Verifies a token's validity and expiry.
    Returns the expiry timestamp and updates the user's active status.
    """
    
    db_token = verify_token_function(request.token, db)
    
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
        
    # 1. Calculate Expiry Timestamp
    expiration_time = db_token.timestamp + TOKEN_VALIDITY_SECONDS
    
    # 2. Update Active User Status using the data retrieved directly from the token object!
    await update_active_user(
        str(db_token.user_id),       # Use the stored user ID
        db_token.username, 
        db_token.user_photo_url      # Use the stored photo URL
    )

    # 3. Return Expiry Timestamp
    return {"timestamp": expiration_time}

@app.post("/api/fivem/download")
async def download_file(request: VerificationRequest, db: Session = Depends(get_db), secret_key: str = Depends(verify_api_secret_key)):
    """
    Downloads the loader file if the request contains a valid token.
    MODIFIED: Reads token from the request body for consistency.
    """
    # 🌟 FIX: Get the token from the request body using the VerificationRequest model.
    db_token = verify_token_function(request.token, db)

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid or missing token")

    # Update the user's active status, just like the /verify endpoint does.
    await update_active_user(
        str(db_token.user_id),
        db_token.username,
        db_token.user_photo_url
    )

    if not os.path.exists(DOWNLOAD_FILE_PATH):
        logger.error(f"Download file not found: {DOWNLOAD_FILE_PATH}")
        raise HTTPException(status_code=500, detail="Download file not found on server.")
        
    return FileResponse(
        path=DOWNLOAD_FILE_PATH,
        media_type='application/octet-stream',
        filename=os.path.basename(DOWNLOAD_FILE_PATH)
    )

# NEW: Endpoint to get last update date
@app.get("/api/fivem/last-update")
async def get_last_update_date(db: Session = Depends(get_db), secret_key: str = Depends(verify_api_secret_key)):
    try:
        # Replace with your actual table and column names
        query = text("""
            SELECT last_post_date 
            FROM xf_forum
            WHERE node_id = :node_id 
            ORDER BY node_id DESC 
            LIMIT 1
        """)
        
        # NOTE: node_id=10 is assumed to be the correct forum ID for FiveM updates
        result = db.execute(query, {"node_id": 10}).fetchone()  
        
        if not result:
            # Handle case where no result is found for node_id 10
            return {"last_update": 0} 
            
        return {"last_update": result.last_post_date}
        
    except SQLAlchemyError as e:
        logger.error(f"Database error getting last update date: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    except Exception as e:
        logger.error(f"Error getting last update date: {e}")
        raise HTTPException(status_code=500, detail="Failed to get last update date")

class UserIdRequest(BaseModel):
    user_id: int

@app.post("/api/subscription/get-expiry-time")
async def get_expiry_time_by_user_id(request: UserIdRequest, db: Session = Depends(get_db), secret_key: str = Depends(verify_api_secret_key)):
    """Retrieves the Unix timestamp of the latest subscription expiry date using the user ID."""
    try:
        user_id = request.user_id
        
        query = text("""
            SELECT end_date 
            FROM xf_user_upgrade_active 
            WHERE user_id = :user_id 
            ORDER BY end_date DESC 
            LIMIT 1
        """)
        
        result = db.execute(query, {"user_id": user_id}).fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail=f"Subscription not found for User ID: {user_id}")
        
        end_date = result.end_date
        
        return {
            "expiry_timestamp": end_date
        }
        
    except SQLAlchemyError as e:
        logger.error(f"Database error getting subscription expiry: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    except HTTPException:
        # Re-raise explicit HTTPException
        raise
    except Exception as e:
        logger.error(f"Error getting subscription expiry: {e}")
        # General failure message
        raise HTTPException(status_code=500, detail="Failed to retrieve subscription expiry time")
# =========================================================================
# 🪵 LOGGING API Endpoint (from logger-server.zip/app.py)
# =========================================================================

# In main.py (inside @app.post("/log"))

@app.post("/log")
async def submit_log(log_data: LogEntryData, request: Request):
    """Handles structured log submissions from the client."""
    # 1. API Key Check
    secret_key = request.headers.get("X-Secret-Key")
    if secret_key != LOGGING_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid X-Secret-Key for logging API")

    # 2. Prepare Data (Use Pydantic V2 conventions)
    # Changed from .dict() to .model_dump() for V2 compatibility
    structured_data = log_data.model_dump() 
    
    # Request data
    request_data = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'method': request.method,
        'path': request.url.path,
        'headers': json.dumps(dict(request.headers)),
        'remote_addr': request.client.host,
        
        # CRITICAL FIX for Pydantic V2: 
        # Use model_dump_json() instead of .json()
        'raw_body': log_data.model_dump_json(indent=2) # <- FIX
    }

    log_entry = {**structured_data, **request_data}
    
    # 3. Insert into DB (rest of function unchanged from previous fix)
    try:
        def insert_log(entry: Dict[str, Any]):
            # ... (SQLite connection and insert logic)
            conn = sqlite3.connect(LOG_DATABASE_FILE)
            c = conn.cursor()
            
            column_names = list(entry.keys())
            placeholders = ', '.join(['?'] * len(column_names))
            columns_str = ', '.join(column_names)
            values = tuple(entry.values())
            
            c.execute(f"INSERT INTO logs ({columns_str}) VALUES ({placeholders})", values)
            last_id = c.lastrowid
            conn.commit()
            conn.close()
            return last_id
            
        last_id = await asyncio.to_thread(insert_log, log_entry) 
        log_entry['id'] = last_id
        
        # 🌟 SSE FIX: Add extra fields needed by the frontend before publishing
        log_entry['profile_url'] = f"https://supreme-cheats.xyz/forum/index.php?members/{log_entry.get('user_id', '')}"
        if not log_entry.get('user_photo_url'):
            log_entry['user_photo_url'] = '/static/default-user.png'
            
        # 🌟 SSE FIX: Publish the newly created log to Redis for real-time streaming
        await redis_manager.publish_log(LOG_CHANNEL, log_entry)

    except Exception as e:
        logger.error(f"Failed to insert log entry: {e}")
        raise HTTPException(status_code=500, detail="Failed to record log")

    # 4. Update Active User Tracker
    log_level = log_entry.get('log_level', 'INFO').upper()
    user_id = log_entry['user_id']
    username = log_entry['username']
    photo_url = log_entry.get('user_photo_url', '')

    if log_level != 'ERROR' and user_id != 'N/A' and user_id:
        await update_active_user(user_id, username, photo_url)
        
    return {"status": "success", "message": "Log recorded"}


# =========================================================================
# 🖥️ DASHBOARD UI Endpoints (from logger-server.zip/app.py)
# =========================================================================

@app.get("/logs/login", response_class=templates.TemplateResponse)
async def get_login(request: Request):
    """Serve the login page or redirect if already logged in."""
    # More direct check: if the session cookie is valid, redirect to the dashboard.
    # 🌟 FIX: Check session in Redis
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if await redis_manager.get_session(session_id):
        return RedirectResponse(url="/logs/view", status_code=status.HTTP_302_FOUND)
    
    # Otherwise, show the login page.
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/logs/login")
async def post_login(request: Request, otp_code: str = Form(...)):
    """Handle 2FA submission."""
    # 🌟 PRODUCTION REFACTOR: Use Redis for distributed login rate limiting.
    client_ip = request.client.host
    login_rate_limit_key = f"login_limit:{client_ip}"
    
    if await redis_manager.check_rate_limit(login_rate_limit_key, limit=10, window=300):
        error_message = "Too many login attempts. Please try again in 5 minutes."
        logger.warning(f"Login rate limit exceeded for IP: {client_ip}")
        return templates.TemplateResponse("login.html", {"request": request, "error": error_message}, status_code=status.HTTP_429_TOO_MANY_REQUESTS)

    if not TOTP_SECRET or TOTP_SECRET == "BASE32_SECRET_KEY_FOR_2FA":
        error_message = "2FA secret is not configured on the server."
        return templates.TemplateResponse("login.html", {"request": request, "error": error_message}, status_code=400)

    # Note: The rate limit is checked before verifying the OTP. A failed attempt still counts.
    # The check_rate_limit method automatically increments the count for the current attempt.

    t = pyotp.TOTP(TOTP_SECRET)
    # 🌟 FIX: Add a valid_window to account for potential time drift between the server and the 2FA device.
    # A window of 1 allows for a tolerance of approximately +/- 60 seconds.
    if t.verify(otp_code, valid_window=1):
        session_id = secrets.token_urlsafe(32)
        # 🌟 FIX: Store session in Redis instead of in-memory dict
        await redis_manager.set_session(session_id, SESSION_TIMEOUT_MINUTES)
        
        response = RedirectResponse(url="/logs/view", status_code=status.HTTP_302_FOUND)
        # Set a secure cookie for the session
        response.set_cookie(
            key=SESSION_COOKIE_NAME, 
            value=session_id, 
            httponly=True,  # 🌟 SECURITY FIX: Prevent client-side script access to the cookie
            secure=True,    # Ensures cookie is only sent over HTTPS
            samesite="strict",
            max_age=SESSION_TIMEOUT_MINUTES * 60
        )
        return response
    else:
        error_message = "Invalid 2FA code."
        logger.warning(f"Invalid 2FA code attempt from IP: {client_ip}")
        return templates.TemplateResponse("login.html", {"request": request, "error": error_message}, status_code=401)

@app.get("/logout")
async def logout(request: Request):
    """Clear session cookie and log out."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        await redis_manager.delete_session(session_id)

    response = RedirectResponse(url="/logs/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return response

@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    """Redirects the root path to the main logs dashboard."""
    return RedirectResponse(url="/logs/view")

@app.get("/logs/view", response_class=HTMLResponse)
async def show_logs(request: Request, session_id: str = Depends(require_dashboard_session_html)):
    filter_text = request.query_params.get("filter", "")
    level_filter = request.query_params.get("level", "")
    try:
        page = int(request.query_params.get("page", "1"))
        if page < 1: page = 1
    except ValueError:
        page = 1
    
    logs_data, total_pages = await asyncio.to_thread(get_logs, filter_text, level_filter, page=page)
    
    logs = [dict(log) for log in logs_data]

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "logs": logs,
        "filter_text": filter_text,
        "level_filter": level_filter,
        "current_page": page,
        "total_pages": total_pages
    })

# 🌟 SSE FIX: New endpoint for streaming logs with Server-Sent Events
async def log_generator(request: Request):
    """Yields server-sent events for new logs from Redis Pub/Sub."""
    try:
        async for log_json in redis_manager.subscribe_to_logs(LOG_CHANNEL):
            if await request.is_disconnected():
                logger.info("Client disconnected from log stream. Closing connection.")
                break
            if log_json:
                yield f"data: {log_json}\n\n"
    except asyncio.CancelledError:
        logger.info("Log stream task cancelled (client disconnected).")
    except Exception as e:
        logger.error(f"Error in log generator: {e}", exc_info=True)

@app.get("/logs/stream")
async def stream_logs(request: Request, session_id: str = Depends(require_dashboard_session_api)):
    """Streams new log entries to the client using Server-Sent Events."""
    return StreamingResponse(log_generator(request), media_type="text/event-stream")


# Use the API dependency for AJAX endpoints
@app.get("/logs/active_users_data")
async def active_users_data(session_id: str = Depends(require_dashboard_session_api)):
    """API endpoint to return the list of active users for the dashboard JS."""
    all_users_data = await redis_manager.get_active_users()
    
    now = datetime.now(timezone.utc)
    cutoff_time = now - timedelta(seconds=ACTIVITY_TIMEOUT_SECONDS)
    active_users = []
    
    for user_data in all_users_data:
        # Ensure user_data is a dictionary, as hgetall returns it.
        if not isinstance(user_data, dict): continue

        last_seen_str = user_data.get('last_seen')
        if not last_seen_str: continue

        last_seen_dt = datetime.fromisoformat(last_seen_str)
        
        if last_seen_dt > cutoff_time:
            time_since = int((now - last_seen_dt).total_seconds())

            # Calculate online duration, with a fallback for older records
            first_seen_str = user_data.get('first_seen', last_seen_str)
            first_seen_dt = datetime.fromisoformat(first_seen_str)
            online_duration = int((now - first_seen_dt).total_seconds())

            active_users.append({
                'username': user_data.get('username'),
                'photo_url': user_data.get('photo_url'),
                'profile_url': user_data.get('profile_url'),
                'time_since': time_since,
                'online_duration': online_duration # Add the new field
            })

    # Sort by time_since (most recently active first)
    active_users.sort(key=lambda x: x['time_since'])

    return JSONResponse(content=active_users)


# =========================================================================
# 🧹 BACKGROUND TASKS
# =========================================================================

async def delete_expired_tokens():
    """Background task to clean up old tokens."""
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL_MINUTES * 60)
        logger.info("Running scheduled token cleanup...")
        
        # Create a new session for the background task
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        try:
            cutoff_timestamp = int(time.time()) - TOKEN_VALIDITY_SECONDS
            # Delete tokens older than the cutoff time
            # NOTE: Assuming you don't use soft deletes
            delete_stmt = text(f"DELETE FROM tokens WHERE timestamp < {cutoff_timestamp}")
            db.execute(delete_stmt)
            db.commit()
            logger.info(f"Token cleanup complete. Deleted tokens older than {datetime.fromtimestamp(cutoff_timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            db.rollback()
            logger.error(f"Error during token cleanup: {e}")
        finally:
            db.close()


@app.on_event("startup")
async def start_background_tasks():
    # 🌟 ROBUSTNESS FIX: Add a retry mechanism for the initial Redis connection.
    # This helps in containerized environments where the app might start before Redis is ready.
    max_retries = 5
    retry_delay = 3  # seconds
    for attempt in range(max_retries):
        try:
            await redis_manager.check_connection()
            break  # Connection successful
        except redis.exceptions.ConnectionError as e:
            if attempt < max_retries - 1:
                logger.warning(f"Could not connect to Redis (attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error("FATAL: Could not connect to Redis after multiple retries. Exiting.")
                raise e # Re-raise the final exception to cause a clean shutdown

    # Start the token cleanup task
    asyncio.create_task(delete_expired_tokens()) 
    logger.info("FastAPI server starting with Redis integration and background tasks.")