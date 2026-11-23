import json
import os
import re
import sqlite3
from contextlib import closing
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("TRACKER_DB", ROOT / "data" / "tracker.sqlite3"))
ASSETS = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/style.css": ("style.css", "text/css")}


def connect():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect()) as db:
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
        """)


def field(data, key, limit, required=False):
    value = data.get(key, "")
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"Invalid {key.replace('_', ' ')}.")
    value = value.strip()
    if required and not value:
        raise ValueError(f"Enter {key.replace('_', ' ')}.")
    return value


def date_field(data, key, required=False):
    value = field(data, key, 10, required)
    if value and (not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) or not date.fromisoformat(value)):
        raise ValueError("Use a valid calendar date.")
    return value


def save_vulnerability(db, data, record_id):
    title = field(data, "title", 200, True)
    cve = field(data, "cve", 32).upper()
    if cve and not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
        raise ValueError("Use a CVE identifier such as CVE-2025-1234.")
    vendor = field(data, "vendor", 200)
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
            (title, cve, vendor, disclosed, notes, links, mitigated, mitigation_date, mitigation_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, values)
        record_id = cursor.lastrowid
    else:
        cursor = db.execute("""
            UPDATE vulnerabilities SET title=?, cve=?, vendor=?, disclosed=?, notes=?,
            links=?, mitigated=?, mitigation_date=?, mitigation_details=? WHERE id=?
        """, (*values, record_id))
        if not cursor.rowcount:
            raise LookupError("Vulnerability not found.")
        db.execute("DELETE FROM affected_products WHERE vulnerability_id=?", (record_id,))
    db.executemany("INSERT INTO affected_products VALUES (?, ?)",
                   [(record_id, pid) for pid in set(products)])
    return {"id": record_id}


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, content, content_type):
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status, data):
        self.respond(status, json.dumps(data).encode(), "application/json")

    def do_GET(self):
        if self.path in ASSETS:
            name, content_type = ASSETS[self.path]
            self.respond(200, (ROOT / "static" / name).read_bytes(), content_type)
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
        self.send_json(200, {"products": products, "vulnerabilities": list(records.values())})

    def do_POST(self):
        self.write_record()

    def do_PUT(self):
        self.write_record()

    def write_record(self):
        product = self.command == "POST" and self.path == "/api/products"
        create = self.command == "POST" and self.path == "/api/vulnerabilities"
        update = re.fullmatch(r"/api/vulnerabilities/([1-9][0-9]{0,17})", self.path) if self.command == "PUT" else None
        if not (product or create or update):
            self.send_json(404, {"error": "Page not found."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Expected JSON."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 150000:
                raise ValueError("Invalid request size.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")
            with closing(connect()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                if product:
                    name = field(data, "name", 120, True)
                    result = {"id": db.execute("INSERT INTO products (name) VALUES (?)", (name,)).lastrowid}
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
            self.send_json(200 if update else 201, result)


if __name__ == "__main__":
    initialize()
    host = os.environ.get("TRACKER_HOST", "127.0.0.1")
    port = int(os.environ.get("TRACKER_PORT", "8080"))
    with ThreadingHTTPServer((host, port), Handler) as server:
        print(f"Vulnerability tracker listening on {host}:{port}", flush=True)
        server.serve_forever()
