"""WMKB Frontend — public-facing Knowledge Base companion to Warehouse Manager.

A small Flask + SQLite app that mirrors the Warehouse Manager Knowledge Base
over a secure, API-key-authenticated read API into its own local store, then
serves it as a modern, public, searchable website with a separate admin area
at /admin for settings and sync control.

Single-file backend by design (like Warehouse Manager). Sync logic lives in
sync.py; the outbound WM API client in wm_client.py.
"""
import os
import re
import json
import uuid
import secrets
import hashlib
from io import BytesIO
from datetime import datetime, timedelta, timezone
from functools import wraps

import sqlite3
from flask import (Flask, render_template, request, jsonify, redirect, url_for,
                   send_from_directory, send_file, session, abort)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash

APP_VERSION = '1.0.3'

# ── Paths & config ────────────────────────────────────────────────────────
DATA_DIR = os.environ.get('WMKB_DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, 'wmkb.db')
CACHE_DIR = os.path.join(DATA_DIR, 'cache')        # synced KB files + featured images
BRANDING_DIR = os.path.join(DATA_DIR, 'branding')  # uploaded logos/favicons/og images
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(BRANDING_DIR, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # branding uploads only

# Served behind a reverse proxy — trust one hop of X-Forwarded-* so request URLs
# (and the Open Graph absolute image URL) reflect the real external https host.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Secret key: env var > file > auto-generate (same pattern as Warehouse Manager)
if os.environ.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
else:
    _SECRET_FILE = os.path.join(DATA_DIR, '.secret_key')
    if os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE) as f:
            app.config['SECRET_KEY'] = f.read().strip()
    else:
        _k = secrets.token_hex(32)
        with open(_SECRET_FILE, 'w') as f:
            f.write(_k)
        os.chmod(_SECRET_FILE, 0o600)
        app.config['SECRET_KEY'] = _k

_SECURE_COOKIES = os.environ.get('WMKB_SECURE_COOKIES', '').lower() in ('1', 'true', 'yes')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=_SECURE_COOKIES,
    REMEMBER_COOKIE_SECURE=_SECURE_COOKIES,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
    REMEMBER_COOKIE_DURATION=60 * 60 * 24 * 30,
)

# Account-lockout policy (admin login)
LOGIN_FAIL_LIMIT = 5
LOCKOUT_MINUTES = 15
PASSWORD_MIN_LENGTH = 10

BRANDING_EXTS = {'png', 'svg', 'jpg', 'jpeg', 'ico'}
_BRANDING_NAME_RE = re.compile(r'^(?:logo|favicon|apple|og)-[a-f0-9]{32}\.(?:png|svg|jpg|jpeg|ico)$', re.IGNORECASE)
BRANDING_ASSETS = ('frontend_logo', 'admin_logo', 'favicon', 'apple_touch_icon', 'og_image')


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    resp.headers.setdefault('Permissions-Policy',
                            'geolocation=(), camera=(), microphone=(), payment=()')
    # The public site is meant to be framed nowhere by default; admin too.
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    if _SECURE_COOKIES:
        resp.headers.setdefault('Strict-Transport-Security',
                                'max-age=31536000; includeSubDomains')
    return resp


# ── Database ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


def _migrate_v1(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            active INTEGER NOT NULL DEFAULT 1,
            failed_login_count INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kb_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_id INTEGER NOT NULL UNIQUE,
            name TEXT NOT NULL,
            slug TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            icon TEXT DEFAULT '',
            doc_count INTEGER DEFAULT 0
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kb_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_id INTEGER NOT NULL UNIQUE,
            category_remote_id INTEGER,
            title TEXT NOT NULL DEFAULT '',
            description TEXT DEFAULT '',
            original_name TEXT DEFAULT '',
            mime_type TEXT DEFAULT '',
            file_size INTEGER DEFAULT 0,
            file_sha256 TEXT DEFAULT '',
            vehicle_fitment TEXT DEFAULT '',
            associated_parts TEXT DEFAULT '[]',
            doc_type TEXT DEFAULT 'document',
            ext TEXT DEFAULT '',
            is_image INTEGER DEFAULT 0,
            has_featured INTEGER DEFAULT 0,
            created_at TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            local_file TEXT DEFAULT '',
            local_featured TEXT DEFAULT '',
            synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_cat ON kb_documents(category_remote_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT,
            finished_at TEXT,
            status TEXT DEFAULT '',
            categories INTEGER DEFAULT 0,
            documents INTEGER DEFAULT 0,
            files_downloaded INTEGER DEFAULT 0,
            error TEXT DEFAULT ''
        )""")


MIGRATIONS = [(1, _migrate_v1)]


def init_db():
    """Apply pending migrations under an fcntl lock (gunicorn multi-worker safe)."""
    import fcntl
    lock_file = open(os.path.join(DATA_DIR, '.migration_lock'), 'w')
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        conn = get_db()
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        current = row['v'] if row['v'] is not None else 0
        for version, fn in MIGRATIONS:
            if version > current:
                fn(conn)
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
                conn.commit()
        conn.close()
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()


# ── Settings helpers (JSON key/value, like Warehouse Manager) ─────────────
def _get_setting(conn, key, default):
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row['value'])
    except Exception:
        return default


def _set_setting(conn, key, value):
    v = json.dumps(value)
    exists = conn.execute("SELECT key FROM app_settings WHERE key = ?", (key,)).fetchone()
    if exists:
        conn.execute("UPDATE app_settings SET value = ? WHERE key = ?", (v, key))
    else:
        conn.execute("INSERT INTO app_settings (key, value) VALUES (?, ?)", (key, v))


DEFAULT_BRANDING = {
    'site_name': 'Knowledge Base',
    'admin_name': 'Knowledge Base Admin',
    'tagline': 'Product guides, instruction sheets & documentation',
    'og_description': 'Browse product instruction sheets, guides, diagrams and documentation.',
    'default_theme': 'light',
    'logo_width': 160,
    'frontend_logo': '', 'admin_logo': '', 'favicon': '',
    'apple_touch_icon': '', 'og_image': '',
}


def get_branding(conn):
    b = dict(DEFAULT_BRANDING)
    b.update(_get_setting(conn, 'branding', {}) or {})
    return b


def get_wm_connection(conn):
    return _get_setting(conn, 'wm_connection', {'base_url': '', 'api_key': ''}) or {}


def get_sync_config(conn):
    cfg = {'enabled': True, 'interval_minutes': 30}
    cfg.update(_get_setting(conn, 'sync_config', {}) or {})
    return cfg


def get_turnstile_config(conn):
    cfg = {'enabled': False, 'site_key': '', 'secret_key': ''}
    cfg.update(_get_setting(conn, 'turnstile_config', {}) or {})
    return cfg


def _sanitize_links(raw):
    """Coerce a stored/incoming list into clean link dicts. Only http(s),
    mailto, tel, and site-relative URLs are allowed (no javascript: etc.)."""
    out = []
    if not isinstance(raw, list):
        return out
    for item in raw[:25]:
        if not isinstance(item, dict):
            continue
        label = str(item.get('label', '') or '').strip()[:60]
        url = str(item.get('url', '') or '').strip()[:500]
        if not label or not url:
            continue
        low = url.lower()
        if not (low.startswith(('http://', 'https://', 'mailto:', 'tel:', '/', '#'))):
            continue
        style = item.get('style', 'link')
        out.append({
            'label': label,
            'url': url,
            'style': 'button' if style == 'button' else 'link',
            'new_tab': bool(item.get('new_tab', True)),
        })
    return out


def get_links(conn):
    return {
        'nav_links': _sanitize_links(_get_setting(conn, 'nav_links', [])),
        'footer_links': _sanitize_links(_get_setting(conn, 'footer_links', [])),
    }


# ── Auth ──────────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
login_manager.login_message = ''


class User(UserMixin):
    def __init__(self, row):
        self.id = row['id']
        self.username = row['username']
        self.display_name = row['display_name'] or row['username']
        self.role = row['role']
        self._active = bool(row['active'])

    @property
    def is_admin(self):
        return self.role == 'admin'

    # Must be a property (not a method): Flask-Login's UserMixin derives
    # is_authenticated from is_active, so a method here makes is_authenticated a
    # bound method (truthy but not JSON-serializable).
    @property
    def is_active(self):
        return self._active


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None


@login_manager.unauthorized_handler
def _unauthorized():
    # API calls get JSON 401; page loads bounce to the login screen.
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('admin_login'))


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def _has_admin():
    """Whether a usable admin account exists. This — not the setup_complete
    flag — is the real gate: once an admin exists, login is always reachable, so
    a half-finished wizard can never trap the user."""
    conn = get_db()
    try:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE active = 1 AND role = 'admin'"
        ).fetchone()['n'] > 0
    finally:
        conn.close()


def _setup_done():
    conn = get_db()
    try:
        return bool(_get_setting(conn, 'setup_complete', False))
    finally:
        conn.close()


def _score_password(pw):
    if not pw or len(pw) < PASSWORD_MIN_LENGTH:
        return False, f'At least {PASSWORD_MIN_LENGTH} characters.'
    classes = sum(bool(re.search(p, pw)) for p in (r'[a-z]', r'[A-Z]', r'\d', r'[^A-Za-z0-9]'))
    if classes < 3:
        return False, 'Mix at least 3 of: lowercase, uppercase, numbers, symbols.'
    return True, None


def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ══════════════════════════════════════════════════════════════════════════
#  PUBLIC SITE
# ══════════════════════════════════════════════════════════════════════════
def _public_branding_ctx():
    conn = get_db()
    b = get_branding(conn)
    last_sync = conn.execute(
        "SELECT finished_at FROM sync_log WHERE status = 'ok' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    links = get_links(conn)
    conn.close()
    b['last_sync'] = last_sync['finished_at'] if last_sync else ''
    b['nav_links'] = links['nav_links']
    b['footer_links'] = links['footer_links']
    return b


@app.route('/')
def public_index():
    return render_template('index.html', branding=_public_branding_ctx(), version=APP_VERSION)


def _doc_public_dict(row):
    d = dict(row)
    try:
        parts = json.loads(d.get('associated_parts') or '[]')
    except Exception:
        parts = []
    return {
        'id': d['remote_id'],
        'category_id': d['category_remote_id'],
        'title': d['title'],
        'description': d['description'],
        'original_name': d['original_name'],
        'mime_type': d['mime_type'],
        'file_size': d['file_size'],
        'ext': d['ext'],
        'is_image': bool(d['is_image']),
        'doc_type': d['doc_type'],
        'vehicle_fitment': d['vehicle_fitment'],
        'associated_parts': [{'number': p.get('number', ''), 'url': p.get('url', '')}
                             for p in parts if p.get('number') or p.get('url')],
        'created_at': d['created_at'],
        'has_file': bool(d['local_file']),
        'has_featured': bool(d['local_featured']),
        'featured_url': f"/kb/{d['remote_id']}/featured" if d['local_featured'] else '',
        'download_url': f"/kb/{d['remote_id']}/download" if d['local_file'] else '',
    }


@app.route('/api/kb/categories')
def api_categories():
    conn = get_db()
    rows = conn.execute(
        "SELECT remote_id AS id, name, slug, sort_order, icon, doc_count "
        "FROM kb_categories ORDER BY sort_order, name COLLATE NOCASE"
    ).fetchall()
    uncategorized = conn.execute(
        "SELECT COUNT(*) AS n FROM kb_documents WHERE category_remote_id IS NULL"
    ).fetchone()['n']
    conn.close()
    return jsonify({'categories': [dict(r) for r in rows], 'uncategorized_count': uncategorized})


@app.route('/api/kb/documents')
def api_documents():
    conn = get_db()
    where, params = [], []
    cat = request.args.get('category_id')
    if cat == 'null':
        where.append("category_remote_id IS NULL")
    elif cat not in (None, '', 'all'):
        try:
            where.append("category_remote_id = ?")
            params.append(int(cat))
        except ValueError:
            pass
    q = (request.args.get('q') or '').strip()
    if q:
        where.append("(title LIKE ? OR description LIKE ? OR original_name LIKE ? "
                     "OR vehicle_fitment LIKE ? OR associated_parts LIKE ?)")
        params += [f"%{q}%"] * 5
    sql = "SELECT * FROM kb_documents"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY sort_order, title COLLATE NOCASE, id"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return jsonify({'documents': [_doc_public_dict(r) for r in rows]})


@app.route('/api/kb/documents/<int:rid>')
def api_document(rid):
    conn = get_db()
    row = conn.execute("SELECT * FROM kb_documents WHERE remote_id = ?", (rid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(_doc_public_dict(row))


@app.route('/kb/<int:rid>/download')
def public_download(rid):
    conn = get_db()
    row = conn.execute(
        "SELECT local_file, original_name, mime_type, ext FROM kb_documents WHERE remote_id = ?",
        (rid,)
    ).fetchone()
    conn.close()
    if not row or not row['local_file']:
        abort(404)
    path = os.path.join(CACHE_DIR, row['local_file'])
    if not os.path.exists(path):
        abort(404)
    # Inline-preview images/PDF; everything else downloads as an attachment.
    inline = (row['ext'] or '').lower() in ('pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'txt')
    return send_file(path, mimetype=row['mime_type'] or 'application/octet-stream',
                     as_attachment=not inline, download_name=row['original_name'] or f'document-{rid}')


@app.route('/kb/<int:rid>/featured')
def public_featured(rid):
    conn = get_db()
    row = conn.execute("SELECT local_featured FROM kb_documents WHERE remote_id = ?", (rid,)).fetchone()
    conn.close()
    if not row or not row['local_featured']:
        abort(404)
    path = os.path.join(CACHE_DIR, row['local_featured'])
    if not os.path.exists(path):
        abort(404)
    return send_file(path, mimetype='image/jpeg')


@app.route('/branding/<asset>')
def serve_branding(asset):
    """Serve an uploaded branding asset. Public: the login page and OG/meta
    tags need these before authentication."""
    conn = get_db()
    b = get_branding(conn)
    conn.close()
    fname = b.get(asset, '') if asset in BRANDING_ASSETS else ''
    if not fname or not _BRANDING_NAME_RE.match(fname):
        abort(404)
    resp = send_from_directory(BRANDING_DIR, fname)
    resp.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"
    if fname.lower().endswith('.svg'):
        resp.headers['Content-Type'] = 'image/svg+xml'
    return resp


# ── Dynamic favicon / apple-touch / OG image shortcuts ──
@app.route('/favicon.ico')
def favicon():
    conn = get_db()
    b = get_branding(conn)
    conn.close()
    if b.get('favicon'):
        return redirect('/branding/favicon')
    return send_from_directory(app.static_folder, 'favicon.png')


# ══════════════════════════════════════════════════════════════════════════
#  ADMIN — pages
# ══════════════════════════════════════════════════════════════════════════
def _admin_branding_ctx():
    conn = get_db()
    b = get_branding(conn)
    ts = get_turnstile_config(conn)
    conn.close()
    b['turnstile_enabled'] = bool(ts.get('enabled'))
    b['turnstile_site_key'] = ts.get('site_key', '') if ts.get('enabled') else ''
    return b


# strict_slashes=False so /admin/ works as well as /admin (Flask 404s the
# trailing-slash form otherwise, which reads as "the admin doesn't exist").
@app.route('/admin', strict_slashes=False)
def admin_home():
    # No admin yet → must run the wizard. Otherwise just require a login.
    if not _has_admin():
        return redirect(url_for('admin_setup'))
    if not current_user.is_authenticated:
        return redirect(url_for('admin_login'))
    return render_template('admin.html', branding=_admin_branding_ctx(), version=APP_VERSION)


@app.route('/admin/setup', strict_slashes=False)
def admin_setup():
    # Fully set up → nothing to do here.
    if _has_admin() and _setup_done():
        return redirect(url_for('admin_home') if current_user.is_authenticated else url_for('admin_login'))
    # An admin exists but the wizard wasn't finished: it can only be resumed by
    # that signed-in admin. An anonymous visitor is sent to log in first.
    if _has_admin() and not current_user.is_authenticated:
        return redirect(url_for('admin_login'))
    # No admin yet (fresh), or a signed-in admin resuming — show the wizard.
    return render_template('setup.html', branding=_admin_branding_ctx(), version=APP_VERSION)


@app.route('/admin/login', strict_slashes=False)
def admin_login():
    # Only force the wizard when there is genuinely no account to log into.
    if not _has_admin():
        return redirect(url_for('admin_setup'))
    if current_user.is_authenticated:
        return redirect(url_for('admin_home'))
    return render_template('login.html', branding=_admin_branding_ctx(), version=APP_VERSION)


@app.route('/admin/logout', strict_slashes=False)
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))


@app.route('/api/auth/turnstile-config')
def public_turnstile_config():
    conn = get_db()
    ts = get_turnstile_config(conn)
    conn.close()
    return jsonify({'enabled': bool(ts.get('enabled')),
                    'site_key': ts.get('site_key', '') if ts.get('enabled') else ''})


# ══════════════════════════════════════════════════════════════════════════
#  ADMIN — auth API
# ══════════════════════════════════════════════════════════════════════════
def _verify_turnstile(token, remote_ip=None):
    import requests as _rq
    conn = get_db()
    cfg = get_turnstile_config(conn)
    conn.close()
    if not cfg.get('enabled'):
        return True, ''
    secret = (cfg.get('secret_key') or '').strip()
    if not secret or not token:
        return False, 'Please complete the challenge'
    try:
        resp = _rq.post('https://challenges.cloudflare.com/turnstile/v0/siteverify',
                        data={'secret': secret, 'response': token, 'remoteip': remote_ip},
                        timeout=10)
        data = resp.json()
        return bool(data.get('success')), '' if data.get('success') else 'Challenge failed'
    except Exception:
        return False, 'Challenge verification error'


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    if not _has_admin():
        return jsonify({'error': 'No account yet — finish setup first', 'redirect': '/admin/setup'}), 409
    data = request.get_json(silent=True) or request.form
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    ok, err = _verify_turnstile(data.get('cf-turnstile-response'), request.remote_addr)
    if not ok:
        return jsonify({'error': err}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    # Lockout check
    if row and row['locked_until']:
        try:
            if datetime.fromisoformat(row['locked_until']) > datetime.now(timezone.utc):
                conn.close()
                return jsonify({'error': 'Account temporarily locked. Try again later.'}), 423
        except Exception:
            pass
    # Timing-safe: always run a hash check.
    stored = row['password_hash'] if row else generate_password_hash('x' * 16)
    valid = check_password_hash(stored, password) and row and row['active']
    if valid:
        conn.execute("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?",
                     (row['id'],))
        # A successful admin login proves the account works — finalize setup so a
        # half-finished wizard can never reappear or trap anyone.
        _set_setting(conn, 'setup_complete', True)
        conn.commit()
        user = User(row)
        conn.close()
        login_user(user, remember=True)
        session.permanent = True
        return jsonify({'success': True, 'redirect': '/admin'})
    if row:
        fails = (row['failed_login_count'] or 0) + 1
        locked = None
        if fails >= LOGIN_FAIL_LIMIT:
            locked = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            fails = 0
        conn.execute("UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?",
                     (fails, locked, row['id']))
        conn.commit()
    conn.close()
    return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/api/auth/me')
@login_required
def api_me():
    return jsonify({'id': current_user.id, 'username': current_user.username,
                    'display_name': current_user.display_name, 'role': current_user.role,
                    'version': APP_VERSION})


# ── First-run setup API ──
@app.route('/api/setup/status')
def setup_status():
    """Lets the wizard resume from the right step instead of dead-ending."""
    conn = get_db()
    c = get_wm_connection(conn)
    done = bool(_get_setting(conn, 'setup_complete', False))
    conn.close()
    return jsonify({
        'has_admin': _has_admin(),
        'authenticated': current_user.is_authenticated,
        'connection_set': bool(c.get('base_url') and c.get('api_key')),
        'setup_complete': done,
    })


@app.route('/api/setup/account', methods=['POST'])
def setup_account():
    # Resume-friendly: if an admin already exists, don't dead-end. A signed-in
    # admin simply advances; anyone else is pointed at the login screen.
    if _has_admin():
        if current_user.is_authenticated and current_user.is_admin:
            return jsonify({'success': True, 'resumed': True})
        return jsonify({'error': 'An admin account already exists. Please sign in.',
                        'redirect': '/admin/login'}), 409
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    display = (data.get('display_name') or '').strip() or username
    password = data.get('password') or ''
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    ok, err = _score_password(password)
    if not ok:
        return jsonify({'error': err}), 400
    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        conn.close()
        return jsonify({'error': 'That username already exists'}), 409
    cur = conn.execute(
        "INSERT INTO users (username, display_name, password_hash, role, active) "
        "VALUES (?, ?, ?, 'admin', 1)",
        (username, display, generate_password_hash(password, method='pbkdf2:sha256'))
    )
    conn.commit()
    uid = cur.lastrowid
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    login_user(User(row), remember=True)
    session.permanent = True
    return jsonify({'success': True})


@app.route('/api/setup/complete', methods=['POST'])
@login_required
def setup_complete():
    conn = get_db()
    _set_setting(conn, 'setup_complete', True)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ══════════════════════════════════════════════════════════════════════════
#  ADMIN — settings API
# ══════════════════════════════════════════════════════════════════════════
@app.route('/api/admin/connection', methods=['GET'])
@admin_required
def get_connection():
    conn = get_db()
    c = get_wm_connection(conn)
    conn.close()
    return jsonify({'base_url': c.get('base_url', ''),
                    'api_key': '********' if c.get('api_key') else ''})


@app.route('/api/admin/connection', methods=['PUT'])
@admin_required
def put_connection():
    data = request.get_json() or {}
    conn = get_db()
    c = get_wm_connection(conn)
    c['base_url'] = (data.get('base_url') or c.get('base_url', '')).strip().rstrip('/')
    key = data.get('api_key', None)
    if key is not None and key != '********':
        c['api_key'] = key.strip()
    _set_setting(conn, 'wm_connection', c)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/admin/connection/test', methods=['POST'])
@admin_required
def test_connection():
    import wm_client
    data = request.get_json() or {}
    conn = get_db()
    c = get_wm_connection(conn)
    conn.close()
    base = (data.get('base_url') or c.get('base_url', '')).strip().rstrip('/')
    key = data.get('api_key', '')
    if key in ('', '********'):
        key = c.get('api_key', '')
    ok, msg = wm_client.test_connection(base, key)
    return (jsonify({'success': True, 'message': msg}) if ok
            else (jsonify({'success': False, 'error': msg}), 400))


@app.route('/api/admin/sync-config', methods=['GET'])
@admin_required
def get_sync_settings():
    conn = get_db()
    cfg = get_sync_config(conn)
    conn.close()
    return jsonify(cfg)


@app.route('/api/admin/sync-config', methods=['PUT'])
@admin_required
def put_sync_settings():
    data = request.get_json() or {}
    conn = get_db()
    cfg = get_sync_config(conn)
    if 'enabled' in data:
        cfg['enabled'] = bool(data['enabled'])
    if 'interval_minutes' in data:
        try:
            cfg['interval_minutes'] = max(5, int(data['interval_minutes']))
        except (TypeError, ValueError):
            pass
    _set_setting(conn, 'sync_config', cfg)
    conn.commit()
    conn.close()
    return jsonify({'success': True, **cfg})


@app.route('/api/admin/sync', methods=['POST'])
@admin_required
def run_sync_now():
    import sync
    result = sync.run_sync()
    status = 200 if result.get('status') == 'ok' else 400
    return jsonify(result), status


@app.route('/api/admin/sync', methods=['GET'])
@admin_required
def sync_status():
    conn = get_db()
    rows = conn.execute("SELECT * FROM sync_log ORDER BY id DESC LIMIT 20").fetchall()
    cat_n = conn.execute("SELECT COUNT(*) AS n FROM kb_categories").fetchone()['n']
    doc_n = conn.execute("SELECT COUNT(*) AS n FROM kb_documents").fetchone()['n']
    conn.close()
    return jsonify({'log': [dict(r) for r in rows],
                    'counts': {'categories': cat_n, 'documents': doc_n}})


# ── Turnstile settings ──
@app.route('/api/admin/turnstile', methods=['GET'])
@admin_required
def get_turnstile():
    conn = get_db()
    cfg = get_turnstile_config(conn)
    conn.close()
    return jsonify({'enabled': bool(cfg.get('enabled')), 'site_key': cfg.get('site_key', ''),
                    'secret_key': '********' if cfg.get('secret_key') else ''})


@app.route('/api/admin/turnstile', methods=['PUT'])
@admin_required
def put_turnstile():
    data = request.get_json() or {}
    conn = get_db()
    cfg = get_turnstile_config(conn)
    cfg['enabled'] = bool(data.get('enabled', cfg.get('enabled')))
    cfg['site_key'] = (data.get('site_key', cfg.get('site_key', '')) or '').strip()
    sk = data.get('secret_key', None)
    if sk is not None and sk != '********':
        cfg['secret_key'] = sk.strip()
    _set_setting(conn, 'turnstile_config', cfg)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ── Branding settings ──
@app.route('/api/admin/branding', methods=['GET'])
@admin_required
def get_branding_api():
    conn = get_db()
    b = get_branding(conn)
    conn.close()
    out = dict(b)
    for a in BRANDING_ASSETS:
        out[a + '_url'] = f'/branding/{a}' if b.get(a) else ''
    return jsonify(out)


@app.route('/api/admin/links', methods=['GET'])
@admin_required
def get_links_api():
    conn = get_db()
    links = get_links(conn)
    conn.close()
    return jsonify(links)


@app.route('/api/admin/links', methods=['PUT'])
@admin_required
def put_links_api():
    data = request.get_json() or {}
    conn = get_db()
    if 'nav_links' in data:
        _set_setting(conn, 'nav_links', _sanitize_links(data.get('nav_links')))
    if 'footer_links' in data:
        _set_setting(conn, 'footer_links', _sanitize_links(data.get('footer_links')))
    conn.commit()
    out = get_links(conn)
    conn.close()
    return jsonify({'success': True, **out})


@app.route('/api/admin/branding', methods=['PUT'])
@admin_required
def put_branding():
    data = request.get_json() or {}
    conn = get_db()
    b = get_branding(conn)
    for k in ('site_name', 'admin_name', 'tagline', 'og_description', 'default_theme'):
        if k in data:
            b[k] = str(data[k])[:200]
    if b.get('default_theme') not in ('light', 'dark'):
        b['default_theme'] = 'light'
    if 'logo_width' in data:
        try:
            b['logo_width'] = max(40, min(600, int(data['logo_width'])))
        except (TypeError, ValueError):
            pass
    _set_setting(conn, 'branding', b)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


def _sanitize_svg(svg_bytes):
    """Strip XSS vectors from an SVG (ported from Warehouse Manager)."""
    import xml.etree.ElementTree as ET
    try:
        text = svg_bytes.decode('utf-8', errors='replace')
    except Exception:
        return None
    ET.register_namespace('', 'http://www.w3.org/2000/svg')
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    if not root.tag.lower().endswith('svg'):
        return None
    dangerous = {'script', 'foreignobject', 'iframe', 'object', 'embed', 'video',
                 'audio', 'animate', 'animatetransform', 'animatemotion', 'set', 'handler'}

    def local(t):
        return t.split('}', 1)[-1].lower()

    def walk(el):
        for child in list(el):
            if local(child.tag) in dangerous:
                el.remove(child)
                continue
            for attr in list(child.attrib.keys()):
                la = attr.split('}', 1)[-1].lower()
                val = (child.attrib.get(attr) or '').strip().lower()
                if la.startswith('on'):
                    del child.attrib[attr]
                    continue
                if la == 'href' or la.endswith(':href'):
                    if val.startswith(('javascript:', 'data:', 'vbscript:', 'file:')):
                        del child.attrib[attr]
                        continue
                if la == 'style' and ('expression(' in val or 'javascript:' in val):
                    del child.attrib[attr]
            walk(child)
    for attr in list(root.attrib.keys()):
        if attr.split('}', 1)[-1].lower().startswith('on'):
            del root.attrib[attr]
    walk(root)
    try:
        return ET.tostring(root, encoding='utf-8', xml_declaration=True)
    except Exception:
        return None


@app.route('/api/admin/branding/<asset>', methods=['POST'])
@admin_required
def upload_branding(asset):
    if asset not in BRANDING_ASSETS:
        return jsonify({'error': 'Unknown asset'}), 400
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'error': 'No file uploaded'}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in BRANDING_EXTS:
        return jsonify({'error': 'Use PNG, JPG, SVG or ICO'}), 400
    buf = f.read()
    prefix = {'frontend_logo': 'logo', 'admin_logo': 'logo', 'favicon': 'favicon',
              'apple_touch_icon': 'apple', 'og_image': 'og'}[asset]
    if ext == 'svg':
        cleaned = _sanitize_svg(buf)
        if cleaned is None:
            return jsonify({'error': 'Invalid or unsafe SVG'}), 400
        buf = cleaned
        new_name = f"{prefix}-{uuid.uuid4().hex}.svg"
    elif ext in ('png', 'jpg', 'jpeg'):
        try:
            from PIL import Image
            img = Image.open(BytesIO(buf))
            img.verify()
        except Exception:
            return jsonify({'error': 'Invalid image file'}), 400
        new_name = f"{prefix}-{uuid.uuid4().hex}.{'jpg' if ext == 'jpeg' else ext}"
    else:  # ico
        new_name = f"{prefix}-{uuid.uuid4().hex}.ico"
    with open(os.path.join(BRANDING_DIR, new_name), 'wb') as out:
        out.write(buf)
    conn = get_db()
    b = get_branding(conn)
    old = b.get(asset, '')
    if old and _BRANDING_NAME_RE.match(old):
        try:
            os.remove(os.path.join(BRANDING_DIR, old))
        except OSError:
            pass
    b[asset] = new_name
    _set_setting(conn, 'branding', b)
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'url': f'/branding/{asset}'})


@app.route('/api/admin/branding/<asset>', methods=['DELETE'])
@admin_required
def delete_branding(asset):
    if asset not in BRANDING_ASSETS:
        return jsonify({'error': 'Unknown asset'}), 400
    conn = get_db()
    b = get_branding(conn)
    old = b.get(asset, '')
    if old and _BRANDING_NAME_RE.match(old):
        try:
            os.remove(os.path.join(BRANDING_DIR, old))
        except OSError:
            pass
    b[asset] = ''
    _set_setting(conn, 'branding', b)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ── User management (admins) ──
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, display_name, role, active, created_at FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return jsonify({'users': [dict(r) for r in rows]})


@app.route('/api/admin/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    display = (data.get('display_name') or '').strip() or username
    if not username:
        return jsonify({'error': 'Username required'}), 400
    ok, err = _score_password(password)
    if not ok:
        return jsonify({'error': err}), 400
    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        conn.close()
        return jsonify({'error': 'Username already exists'}), 409
    conn.execute("INSERT INTO users (username, display_name, password_hash, role, active) "
                 "VALUES (?, ?, ?, 'admin', 1)",
                 (username, display, generate_password_hash(password, method='pbkdf2:sha256')))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 201


@app.route('/api/admin/users/<int:uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == current_user.id:
        return jsonify({'error': "You can't delete your own account"}), 400
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) AS n FROM users WHERE active = 1").fetchone()['n']
    if n <= 1:
        conn.close()
        return jsonify({'error': 'At least one admin must remain'}), 400
    conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/admin/password', methods=['PUT'])
@login_required
def change_password():
    data = request.get_json() or {}
    current = data.get('current_password') or ''
    new = data.get('new_password') or ''
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if not row or not check_password_hash(row['password_hash'], current):
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 400
    ok, err = _score_password(new)
    if not ok:
        conn.close()
        return jsonify({'error': err}), 400
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                 (generate_password_hash(new, method='pbkdf2:sha256'), current_user.id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/admin/about')
@admin_required
def about():
    changelog = ''
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CHANGELOG.md')
    if os.path.exists(p):
        with open(p) as f:
            changelog = f.read()
    return jsonify({'version': APP_VERSION, 'changelog': changelog})


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5070)), debug=True)
