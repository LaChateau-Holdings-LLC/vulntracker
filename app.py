import base64
import binascii
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import date
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from urllib.error import URLError

from tracker_auth import AuthError, OIDC, digest

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("TRACKER_DB", ROOT / "data" / "tracker.sqlite3"))
ASSETS = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/style.css": ("style.css", "text/css"), "/login.js": ("login.js", "text/javascript"), "/favicon.png": ("favicon.png", "image/png")}
BRAND_IMAGE_LIMIT = 256 * 1024
AUTH = OIDC()
FLOW_COOKIE = "__Host-tracker-oidc"
SESSION_COOKIE = "__Host-tracker-session"
SESSION_LIFETIME = 8 * 60 * 60


def connect():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect()) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                cve TEXT NOT NULL,
                vendor TEXT NOT NULL,
                disclosed TEXT NOT NULL,
                notes TEXT NOT NULL,
                links TEXT NOT NULL,
                mitigated INTEGER NOT NULL,
                mitigation_date TEXT NOT NULL,
                mitigation_details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS affected_products (
                vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
                product_id INTEGER NOT NULL REFERENCES products(id),
                PRIMARY KEY (vulnerability_id, product_id)
            );
            CREATE TABLE IF NOT EXISTS inventory (
                product_id INTEGER NOT NULL REFERENCES products(id),
                version TEXT NOT NULL,
                quantity INTEGER NOT NULL CHECK (quantity > 0),
                PRIMARY KEY (product_id, version)
            );
            CREATE TABLE IF NOT EXISTS branding (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL DEFAULT 'Vulnerability Tracker',
                organization TEXT NOT NULL DEFAULT '',
                logo BLOB,
                logo_type TEXT,
                favicon BLOB,
                favicon_type TEXT,
                revision INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO branding (id) VALUES (1);
            CREATE TABLE IF NOT EXISTS oidc_flows (
                state TEXT PRIMARY KEY,
                binding TEXT NOT NULL,
                verifier TEXT NOT NULL,
                nonce TEXT NOT NULL,
                config TEXT NOT NULL,
                expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oidc_sessions (
                token TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                admin INTEGER NOT NULL,
                config TEXT NOT NULL,
                expires INTEGER NOT NULL
            );
        """)
        db.execute("BEGIN IMMEDIATE")
        if "kind" not in {column["name"] for column in db.execute("PRAGMA table_info(products)")}:
            db.execute("""
                ALTER TABLE products ADD COLUMN kind TEXT NOT NULL DEFAULT 'unclassified'
                CHECK (kind IN ('hardware', 'software', 'unclassified'))
            """)

        if "severity" not in {column["name"] for column in db.execute("PRAGMA table_info(vulnerabilities)")}:
            db.execute("""
                ALTER TABLE vulnerabilities ADD COLUMN severity TEXT NOT NULL DEFAULT ''
                CHECK (severity IN ('', 'low', 'medium', 'high', 'critical'))
            """)


def field(data, key, limit, required=False):
    value = data.get(key, "")
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"Invalid {key.replace('_', ' ')}.")
    value = value.strip()
    if required and not value:
        raise ValueError(f"Enter {key.replace('_', ' ')}.")
    return value


def read_branding(db):
    return dict(db.execute("""
        SELECT name, organization, logo IS NOT NULL AS has_logo,
               favicon IS NOT NULL AS has_favicon, revision FROM branding WHERE id = 1
    """).fetchone())


def brand_image(value, key):
    if value is None:
        return None, None
    if not isinstance(value, str) or len(value) > 350_000:
        raise ValueError(f"Choose a {key} image up to 256 KB.")
    try:
        image = base64.b64decode(value, validate=True)
    except binascii.Error:
        raise ValueError(f"The {key} image could not be read.") from None
    if len(image) > BRAND_IMAGE_LIMIT:
        raise ValueError(f"Choose a {key} image up to 256 KB.")
    if image.startswith(b"\x89PNG\r\n\x1a\n"):
        return image, "image/png"
    if image.startswith(b"\xff\xd8\xff"):
        return image, "image/jpeg"
    if image.startswith(b"RIFF") and image[8:12] == b"WEBP":
        return image, "image/webp"
    if key == "favicon" and image.startswith(b"\x00\x00\x01\x00"):
        return image, "image/x-icon"
    raise ValueError(f"Choose a supported image for the {key}.")


def save_branding(db, data):
    name = field(data, "name", 80, True)
    organization = field(data, "organization", 120)
    db.execute("UPDATE branding SET name = ?, organization = ?, revision = revision + 1 WHERE id = 1",
               (name, organization))
    for key in ("logo", "favicon"):
        if key in data:
            # Column names come from the fixed list above.
            db.execute(f"UPDATE branding SET {key} = ?, {key}_type = ? WHERE id = 1",
                       brand_image(data[key], key))
    return read_branding(db)


def date_field(data, key, required=False):
    value = field(data, key, 10, required)
    if value and (not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) or not date.fromisoformat(value)):
        raise ValueError("Use a valid calendar date.")
    return value


def product_kind(data, required=False):
    kind = field(data, "kind", 20, required)
    if kind and kind not in {"hardware", "software"}:
        raise ValueError("Choose Hardware or Software.")
    return kind or "unclassified"


def save_inventory(db, data):
    product_id = data.get("product_id")
    quantity = data.get("quantity")
    version = field(data, "version", 120)
    if type(product_id) is not int or not 0 < product_id < 2**63:
        raise ValueError("Select a product.")
    if type(quantity) is not int or not 0 <= quantity <= 1_000_000:
        raise ValueError("Enter a whole quantity between 0 and 1,000,000.")
    if not db.execute("SELECT 1 FROM products WHERE id = ?", (product_id,)).fetchone():
        raise ValueError("Select an existing product.")
    if quantity:
        db.execute("""
            INSERT INTO inventory (product_id, version, quantity) VALUES (?, ?, ?)
            ON CONFLICT (product_id, version) DO UPDATE SET quantity = excluded.quantity
        """, (product_id, version, quantity))
    else:
        db.execute("DELETE FROM inventory WHERE product_id = ? AND version = ?", (product_id, version))
    return {"product_id": product_id}


def save_vulnerability(db, data, record_id):
    title = field(data, "title", 200, True)
    cve = field(data, "cve", 32).upper()
    if cve and not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
        raise ValueError("Use a CVE identifier such as CVE-2025-1234.")
    vendor = field(data, "vendor", 200)
    severity = None
    if "severity" in data:
        severity = field(data, "severity", 8, True)
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("Choose Low, Medium, High, or Critical severity.")
    disclosed = date_field(data, "disclosed", True)
    notes = field(data, "notes", 12000)
    links = [line.strip() for line in field(data, "links", 8000).splitlines() if line.strip()]
    for link in links:
        parsed = urlsplit(link)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or re.search(r"\s", link):
            raise ValueError("Enter one HTTP or HTTPS link per line.")
    mitigated = data.get("mitigated")
    if type(mitigated) is not bool:
        raise ValueError("Choose a mitigation status.")
    mitigation_date = date_field(data, "mitigation_date", True) if mitigated else ""
    details = field(data, "mitigation_details", 12000, True) if mitigated else ""
    products = data.get("products")
    if not isinstance(products, list) or not products or any(
        type(pid) is not int or not 0 < pid < 2**63 for pid in products
    ):
        raise ValueError("Select at least one affected product.")
    if not set(products) <= {row["id"] for row in db.execute("SELECT id FROM products")}:
        raise ValueError("One of the selected products no longer exists.")
    values = (title, cve, vendor, disclosed, notes, "\n".join(links), mitigated,
              mitigation_date, details)
    if record_id is None:
        cursor = db.execute("""
            INSERT INTO vulnerabilities
            (title, cve, vendor, disclosed, notes, links, mitigated, mitigation_date, mitigation_details, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (*values, severity or ""))
        record_id = cursor.lastrowid
    else:
        cursor = db.execute("""
            UPDATE vulnerabilities SET title=?, cve=?, vendor=?, disclosed=?, notes=?,
            links=?, mitigated=?, mitigation_date=?, mitigation_details=?,
            severity=COALESCE(?, severity) WHERE id=?
        """, (*values, severity, record_id))
        if not cursor.rowcount:
            raise LookupError("Vulnerability not found.")
        db.execute("DELETE FROM affected_products WHERE vulnerability_id=?", (record_id,))
    db.executemany("INSERT INTO affected_products VALUES (?, ?)",
                   [(record_id, pid) for pid in set(products)])
    return {"id": record_id}


class Handler(BaseHTTPRequestHandler):
    def log_request(self, code="-", size="-"):
        self.log_message('"%s %s %s" %s %s', self.command, urlsplit(self.path).path, self.request_version, code, size)

    def respond(self, status, content, content_type, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status, data):
        self.respond(status, json.dumps(data).encode(), "application/json")

    def cookie(self, name):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return ""
        return cookies[name].value if name in cookies else ""

    def session(self):
        if AUTH.mode == "off":
            return None
        with closing(connect()) as db:
            return AUTH.session(db, self.cookie(SESSION_COOKIE))

    @staticmethod
    def set_cookie(name, value, age):
        return ("Set-Cookie", f"{name}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite=Lax")

    def auth_redirect(self, location, *cookies):
        self.respond(303, b"", "text/plain", (("Location", location), *cookies))

    def auth_status(self):
        user = self.session()
        self.send_json(200, {
            "mode": AUTH.mode, "provider": AUTH.provider_name, "redirect_uri": AUTH.redirect_uri,
            "user": {"name": user["name"], "admin": bool(user["admin"])} if user else None,
        })

    def auth_login(self):
        with closing(connect()) as db, db:
            location, binding = AUTH.start(db)
        self.auth_redirect(location, self.set_cookie(FLOW_COOKIE, binding, 600))

    def auth_callback(self, query):
        values = parse_qs(query, max_num_fields=20)
        if "error" in values:
            raise AuthError("The identity provider did not complete sign-in.")
        state = values.get("state", [])
        codes = values.get("code", [])
        binding = self.cookie(FLOW_COOKIE)
        if len(state) != 1 or len(codes) != 1 or not binding:
            raise AuthError("The sign-in request expired. Start again from the tracker.")
        # Consume the state before talking to the provider, including on failure.
        with closing(connect()) as db, db:
            flow = db.execute("""
                DELETE FROM oidc_flows WHERE state = ? AND binding = ? AND config = ? AND expires > ?
                RETURNING verifier, nonce
            """, (digest(state[0]), digest(binding), AUTH.fingerprint, int(time.time()))).fetchone()
        if not flow:
            raise AuthError("The sign-in request expired. Start again from the tracker.")
        name, admin = AUTH.finish(flow, codes[0])
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with closing(connect()) as db, db:
            db.execute("DELETE FROM oidc_sessions WHERE expires <= ? OR token = ?",
                       (now, digest(self.cookie(SESSION_COOKIE))))
            db.execute("INSERT INTO oidc_sessions VALUES (?, ?, ?, ?, ?)",
                       (digest(token), name, admin, AUTH.fingerprint, now + SESSION_LIFETIME))
        target = "/?signin=test" if AUTH.mode == "test" else "/"
        self.auth_redirect(target, self.set_cookie(FLOW_COOKIE, "", 0),
                           self.set_cookie(SESSION_COOKIE, token, SESSION_LIFETIME))

    def auth_logout(self):
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Expected JSON."})
            return
        with closing(connect()) as db, db:
            db.execute("DELETE FROM oidc_sessions WHERE token = ?", (digest(self.cookie(SESSION_COOKIE)),))
        self.respond(200, b"{}", "application/json", (self.set_cookie(SESSION_COOKIE, "", 0),))

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/api/auth":
            self.auth_status()
            return
        if AUTH.mode != "off" and path in {"/auth/login", "/auth/callback"}:
            try:
                if path == "/auth/login":
                    self.auth_login()
                else:
                    self.auth_callback(parsed.query)
            except AuthError as error:
                self.respond(400, str(error).encode(), "text/plain")
            except (URLError, TimeoutError, ValueError, TypeError, KeyError):
                self.respond(502, b"Could not complete OIDC sign-in. Check provider settings and try again.", "text/plain")
            return
        if AUTH.mode == "required" and path not in {"/style.css", "/login.js", "/favicon.png"} and not self.session():
            if path == "/":
                self.respond(200, (ROOT / "static" / "login.html").read_bytes(), "text/html")
            else:
                self.send_json(401, {"error": "Sign in to open the tracker."})
            return
        if path in ASSETS:
            name, content_type = ASSETS[path]
            self.respond(200, (ROOT / "static" / name).read_bytes(), content_type)
            return
        if self.path == "/api/branding":
            with closing(connect()) as db:
                self.send_json(200, read_branding(db))
            return
        image_path = urlsplit(self.path).path
        if image_path in {"/branding/logo", "/branding/favicon"}:
            key = image_path.rsplit("/", 1)[1]
            with closing(connect()) as db:
                image, content_type = db.execute(f"SELECT {key}, {key}_type FROM branding WHERE id = 1").fetchone()
            if image:
                self.respond(200, image, content_type)
            else:
                self.send_json(404, {"error": "Image not found."})
            return
        if self.path != "/api/tracker":
            self.send_json(404, {"error": "Page not found."})
            return
        with closing(connect()) as db:
            db.execute("BEGIN")
            products = [dict(row) for row in db.execute("SELECT * FROM products ORDER BY name")]
            records = {row["id"]: dict(row, products=[]) for row in db.execute(
                "SELECT * FROM vulnerabilities ORDER BY disclosed DESC, id DESC")}
            for row in db.execute("SELECT vulnerability_id, product_id FROM affected_products"):
                records[row["vulnerability_id"]]["products"].append(row["product_id"])
            inventory = [dict(row) for row in db.execute("""
                SELECT inventory.* FROM inventory JOIN products ON products.id = inventory.product_id
                ORDER BY products.name, inventory.version COLLATE NOCASE
            """)]
        self.send_json(200, {"products": products, "vulnerabilities": list(records.values()), "inventory": inventory})

    def do_POST(self):
        if AUTH.mode != "off" and self.path == "/auth/logout":
            self.auth_logout()
            return
        self.write_record()

    def do_PUT(self):
        self.write_record()

    def write_record(self):
        branding = self.command == "PUT" and self.path == "/api/branding"
        if AUTH.mode == "required":
            user = self.session()
            if not user:
                self.send_json(401, {"error": "Sign in to open the tracker."})
                return
            if branding and not user["admin"]:
                self.send_json(403, {"error": "Only tracker administrators can change branding."})
                return
        product = self.command == "POST" and self.path == "/api/products"
        classify = re.fullmatch(r"/api/products/([1-9][0-9]{0,17})", self.path) if self.command == "PUT" else None
        inventory = self.command == "PUT" and self.path == "/api/inventory"
        create = self.command == "POST" and self.path == "/api/vulnerabilities"
        update = re.fullmatch(r"/api/vulnerabilities/([1-9][0-9]{0,17})", self.path) if self.command == "PUT" else None
        if not (branding or product or classify or inventory or create or update):
            self.send_json(404, {"error": "Page not found."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Expected JSON."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= (750_000 if branding else 150_000):
                raise ValueError("Invalid request size.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")
            with closing(connect()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                if branding:
                    result = save_branding(db, data)
                elif product:
                    name = field(data, "name", 120, True)
                    kind = product_kind(data)
                    product_id = db.execute("INSERT INTO products (name, kind) VALUES (?, ?)", (name, kind)).lastrowid
                    version = field(data, "version", 120)
                    quantity = data.get("quantity")
                    result = {"id": product_id}
                    if version or quantity is not None:
                        if type(quantity) is not int or quantity < 1:
                            raise ValueError("Enter a positive whole quantity for the initial inventory.")
                        entry = {"product_id": product_id, "version": version, "quantity": quantity}
                        save_inventory(db, entry)
                        result["inventory"] = entry
                elif classify:
                    product_id = int(classify[1])
                    cursor = db.execute("UPDATE products SET kind = ? WHERE id = ?",
                                        (product_kind(data, required=True), product_id))
                    if not cursor.rowcount:
                        raise LookupError("Product not found.")
                    result = {"id": product_id}
                elif inventory:
                    result = save_inventory(db, data)
                else:
                    result = save_vulnerability(db, data, int(update[1]) if update else None)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "Invalid JSON."})
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
        except LookupError as error:
            self.send_json(404, {"error": str(error)})
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "A product with that name already exists."})
        else:
            self.send_json(200 if branding or update or inventory or classify else 201, result)


if __name__ == "__main__":
    AUTH = OIDC.from_env()
    initialize()
    host = os.environ.get("TRACKER_HOST", "127.0.0.1")
    port = int(os.environ.get("TRACKER_PORT", "8080"))
    with ThreadingHTTPServer((host, port), Handler) as server:
        print(f"Vulnerability tracker listening on {host}:{port}", flush=True)
        server.serve_forever()
