import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import string
import base64
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# ─────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(tempfile.gettempdir(), "cybershield_web.db")
PORT     = 8080

# ─────────────────────────────────────────────
#  COMMON PASSWORDS
# ─────────────────────────────────────────────
COMMON_PASSWORDS = {
    "123456", "password", "admin", "qwerty", "letmein", "welcome",
    "111111", "password1", "abc123", "iloveyou", "monkey", "123456789",
    "1234567890", "12345678", "dragon", "master", "pass", "root",
    "sunshine", "shadow", "12345", "1234", "test", "guest", "login",
    "hello", "superman", "batman", "trustno1", "baseball", "football",
}

# ─────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        masked TEXT,
        strength TEXT,
        score INTEGER,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT
    )""")
    conn.commit()
    conn.close()
    print(f"  [DB] SQLite database ready at {DB_PATH}")

def db_insert_history(masked, strength, score):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO history (masked, strength, score) VALUES (?,?,?)",
                 (masked, strength, score))
    conn.commit()
    conn.close()

def db_get_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT masked, strength, score, ts FROM history ORDER BY id DESC LIMIT 20")
    rows = [{"masked": r[0], "strength": r[1], "score": r[2], "ts": r[3]} for r in c.fetchall()]
    conn.close()
    return rows

def db_clear_history():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM history")
    conn.commit()
    conn.close()

def db_get_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def db_create_user(username, pw_hash):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (username, pw_hash))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
#  SECURITY ENGINE
# ─────────────────────────────────────────────
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def calc_entropy(pw: str) -> int:
    pool = 0
    if re.search(r'[a-z]', pw): pool += 26
    if re.search(r'[A-Z]', pw): pool += 26
    if re.search(r'[0-9]', pw): pool += 10
    if re.search(r'[^a-zA-Z0-9]', pw): pool += 32
    return int(len(pw) * math.log2(pool)) if pool else 0

def crack_time_str(entropy: int) -> str:
    secs = (2 ** entropy) / 1e10
    if secs < 1:        return "< 1 second"
    if secs < 60:       return f"{int(secs)} seconds"
    if secs < 3600:     return f"{int(secs/60)} minutes"
    if secs < 86400:    return f"{int(secs/3600)} hours"
    if secs < 31536000: return f"{int(secs/86400)} days"
    if secs < 3.15e9:   return f"{int(secs/31536000)} years"
    return "> 100 years"

def password_score(pw: str) -> int:
    if not pw or pw.lower() in COMMON_PASSWORDS:
        return 0
    s = 0
    if len(pw) >= 8:  s += 1
    if len(pw) >= 12: s += 1
    if re.search(r'[a-z]', pw): s += 1
    if re.search(r'[A-Z]', pw): s += 1
    if re.search(r'[0-9]', pw): s += 1
    if re.search(r'[^a-zA-Z0-9]', pw): s += 1
    return min(s, 5)

SCORE_LABELS = ["", "Very Weak", "Weak", "Fair", "Strong", "Very Strong"]

def analyze_password(pw: str) -> dict:
    score = password_score(pw)
    entropy = calc_entropy(pw)
    char_types = sum([
        bool(re.search(r'[a-z]', pw)),
        bool(re.search(r'[A-Z]', pw)),
        bool(re.search(r'[0-9]', pw)),
        bool(re.search(r'[^a-zA-Z0-9]', pw)),
    ])
    is_common = pw.lower() in COMMON_PASSWORDS
    suggestions = []
    rules = [
        (len(pw) >= 8,  "Use at least 8 characters"),
        (len(pw) >= 12, "Use 12+ characters for better security"),
        (bool(re.search(r'[A-Z]', pw)), "Add uppercase letters (A–Z)"),
        (bool(re.search(r'[a-z]', pw)), "Add lowercase letters (a–z)"),
        (bool(re.search(r'[0-9]', pw)), "Add numbers (0–9)"),
        (bool(re.search(r'[^a-zA-Z0-9]', pw)), "Add special characters (!@#$%)"),
        (not is_common, "Avoid commonly used passwords"),
    ]
    for ok, msg in rules:
        suggestions.append({"ok": ok, "msg": ("✓ " if ok else "✗ ") + msg})

    # Save to history
    if len(pw) >= 4:
        masked = pw[:2] + "•" * max(2, len(pw) - 4) + pw[-2:]
        db_insert_history(masked, SCORE_LABELS[score] or "Very Weak", score)

    return {
        "score": score,
        "label": SCORE_LABELS[score] or "Very Weak",
        "entropy": entropy,
        "char_types": char_types,
        "length": len(pw),
        "crack_time": crack_time_str(entropy),
        "is_common": is_common,
        "suggestions": suggestions,
        "pct": [0, 15, 30, 55, 80, 100][score],
    }

# ─────────────────────────────────────────────
#  ENCRYPTION ENGINE
# ─────────────────────────────────────────────
def caesar_cipher(text: str, shift: int) -> str:
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)

def xor_encrypt(text: str, key: int = 42) -> str:
    return " ".join(format(ord(c) ^ key, '02x') for c in text)

def xor_decrypt(hex_str: str, key: int = 42) -> str:
    try:
        return "".join(chr(int(h, 16) ^ key) for h in hex_str.strip().split())
    except Exception:
        return "Invalid XOR input"

def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def b64_decode(text: str) -> str:
    try:
        return base64.b64decode(text.encode()).decode()
    except Exception:
        return "Invalid Base64 input"

# ─────────────────────────────────────────────
#  PASSWORD GENERATOR
# ─────────────────────────────────────────────
def generate_password(length=16, upper=True, lower=True, digits=True, symbols=True) -> str:
    pool = ""
    guaranteed = []
    if upper:
        pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if lower:
        pool += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if digits:
        pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if symbols:
        sym = "!@#$%^&*()-_=+[]{}|;:,.?"
        pool += sym
        guaranteed.append(secrets.choice(sym))
    if not pool:
        return "Select at least one character type"
    chars = guaranteed + [secrets.choice(pool) for _ in range(length - len(guaranteed))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars[:length])

# ─────────────────────────────────────────────
#  HTTP SERVER
# ─────────────────────────────────────────────
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".ico":  "image/x-icon",
    ".png":  "image/png",
    ".json": "application/json",
}

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        method = args[0] if args else ''
        path   = args[1] if len(args) > 1 else ''
        code   = args[2] if len(args) > 2 else ''
        print(f"  [{code}] {method.split()[0] if method else 'REQ'} {path}")

    # ── Static files ───────────────────────────
    def serve_file(self, filepath):
        if not os.path.isfile(filepath):
            self.send_error(404, "Not found")
            return
        ext = os.path.splitext(filepath)[1].lower()
        mime = MIME.get(ext, "application/octet-stream")
        with open(filepath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    # ── JSON helpers ───────────────────────────
    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def json_response(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    # ── GET ────────────────────────────────────
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/":
            self.serve_file(os.path.join(BASE_DIR, "index.html"))
        elif path in ("/style.css", "/app.js"):
            self.serve_file(os.path.join(BASE_DIR, path.lstrip("/")))
        elif path == "/api/history":
            self.json_response({"history": db_get_history()})
        else:
            self.send_error(404, "Not found")

    # ── DELETE ─────────────────────────────────
    def do_DELETE(self):
        path = urlparse(self.path).path
        if path == "/api/history":
            db_clear_history()
            self.json_response({"ok": True})
        else:
            self.send_error(404)

    # ── OPTIONS (CORS preflight) ───────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── POST ───────────────────────────────────
    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.read_json()
        except Exception:
            self.json_response({"error": "Invalid JSON"}, 400)
            return

        # ── /api/analyze ──────────────────────
        if path == "/api/analyze":
            pw = body.get("password", "")
            if not isinstance(pw, str):
                self.json_response({"error": "password must be a string"}, 400)
                return
            self.json_response(analyze_password(pw))

        # ── /api/encrypt ──────────────────────
        elif path == "/api/encrypt":
            text   = body.get("text", "")
            cipher = body.get("cipher", "caesar")
            if cipher == "caesar":
                result = caesar_cipher(text, 13)
                info = "ROT-13 Caesar cipher"
            elif cipher == "xor":
                result = xor_encrypt(text)
                info = "XOR with key=42 (hex output)"
            else:
                result = b64_encode(text)
                info = "Base64 encoding"
            self.json_response({"result": result, "cipher": cipher, "info": info})

        # ── /api/decrypt ──────────────────────
        elif path == "/api/decrypt":
            text   = body.get("text", "")
            cipher = body.get("cipher", "caesar")
            if cipher == "caesar":
                result = caesar_cipher(text, -13)
                info = "ROT-13 Caesar decrypted"
            elif cipher == "xor":
                result = xor_decrypt(text)
                info = "XOR decrypted (key=42)"
            else:
                result = b64_decode(text)
                info = "Base64 decoded"
            self.json_response({"result": result, "cipher": cipher, "info": info})

        # ── /api/generate ─────────────────────
        elif path == "/api/generate":
            pw = generate_password(
                length=int(body.get("length", 16)),
                upper=bool(body.get("upper", True)),
                lower=bool(body.get("lower", True)),
                digits=bool(body.get("digits", True)),
                symbols=bool(body.get("symbols", True)),
            )
            self.json_response({"password": pw, **analyze_password(pw)})

        # ── /api/login ────────────────────────
        elif path == "/api/login":
            username = body.get("username", "").strip()
            password = body.get("password", "")
            if not username or not password:
                self.json_response({"ok": False, "msg": "Username and password required"}, 400)
                return
            pw_hash = hash_password(password)
            stored  = db_get_user(username)
            if stored is None:
                db_create_user(username, pw_hash)
                self.json_response({
                    "ok": True,
                    "action": "registered",
                    "msg": f"Account created for '{username}'.",
                    "hash": pw_hash,
                })
            elif stored == pw_hash:
                self.json_response({
                    "ok": True,
                    "action": "login",
                    "msg": f"Welcome back, {username}!",
                    "hash": pw_hash,
                })
            else:
                self.json_response({
                    "ok": False,
                    "action": "failed",
                    "msg": f"Incorrect password for '{username}'.",
                })

        else:
            self.send_error(404, "Unknown endpoint")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║   CYBERSHIELD PASSWORD SYSTEM        ║")
    print("  ║   Python HTTP Server                 ║")
    print(f" ║   http://localhost:{PORT}            ║")
    print("  ╚══════════════════════════════════════╝")
    print()
    print("  Press Ctrl+C to stop the server.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [SERVER] Shutting down. Goodbye!")
        server.shutdown()