# 1. app_pg.py
```python
import os
import re
import random, string
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

import bcrypt
from sqlalchemy import Column, Integer, String, DateTime, select
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy import create_engine

APP_TITLE = "short321 – URL Shortener"
REDIRECT_HOME_TO = os.getenv("REDIRECT_HOME_TO", "https://pmitconsulting.com")
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_PASSWORD_BCRYPT = os.getenv("ADMIN_PASSWORD_BCRYPT")
PUBLIC_HOSTNAME = os.getenv("PUBLIC_HOSTNAME", "short321.com")

RESERVED_SLUGS = {"admin", "logout", "login", "create", "delete", "static", "favicon.ico", "robots.txt"}
SLUG_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite:///data/urls.db"
engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)
Base = declarative_base()

class Link(Base):
    __tablename__ = "links"
    slug = Column(String(64), primary_key=True)
    dest_url = Column(String(2048), nullable=False)
    hits = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

Base.metadata.create_all(engine)

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY or __import__("secrets").token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

def is_logged_in():
    return bool(session.get("admin"))

def check_password(plaintext: str) -> bool:
    return ADMIN_PASSWORD_BCRYPT and bcrypt.checkpw(plaintext.encode(), ADMIN_PASSWORD_BCRYPT.encode())

def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    parsed = urlparse(u)
    return u if parsed.scheme else "https://" + u

def generate_slug(n: int = 6) -> str:
    alphabet = string.ascii_letters + string.digits
    with Session(engine) as s:
        while True:
            candidate = "".join(random.choice(alphabet) for _ in range(n))
            if candidate in RESERVED_SLUGS:
                continue
            if not s.get(Link, candidate):
                return candidate

BASE_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1"><title>{{ title or 'Admin' }}</title><link rel=preconnect href=https://fonts.googleapis.com><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel=stylesheet><script src="https://cdn.tailwindcss.com"></script><style>body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}</style></head><body class="bg-slate-50 text-slate-900"><div class=max-w-4xl mx-auto p-6><div class="flex items-center justify-between mb-6"><h1 class="text-2xl font-bold">short321 Admin</h1>{% if logged_in %}<a href="{{ url_for('logout') }}" class="text-sm text-slate-500 hover:text-slate-800">Log out</a>{% endif %}</div>{% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}<div class=space-y-2 mb-4>{% for category, message in messages %}<div class="p-3 rounded-lg text-sm {{ 'bg-emerald-100 text-emerald-900' if category=='success' else 'bg-rose-100 text-rose-900' }}">{{ message }}</div>{% endfor %}</div>{% endif %}{% endwith %}{% block content %}{% endblock %}<p class="mt-10 text-xs text-slate-400">&copy; {{ year }} short321.com</p></div></body></html>"""
LOGIN_HTML = """{% extends 'base.html' %}{% block content %}<div class="bg-white rounded-2xl shadow p-6"><h2 class="text-lg font-semibold mb-4">Admin Login</h2><form method=post action="{{ url_for('login') }}" class=space-y-4><label class="block text-sm mb-1" for=password>Password</label><input id=password name=password type=password required class="w-full rounded-xl border p-2"><button class="rounded-xl px-4 py-2 bg-slate-900 text-white mt-2">Sign in</button></form></div>{% endblock %}"""
DASHBOARD_HTML = """{% extends 'base.html' %}{% block content %}<div class="bg-white rounded-2xl shadow p-6"><h2 class="text-lg font-semibold mb-4">Create a Short Link</h2><form method=post action="{{ url_for('create') }}" class="grid md:grid-cols-6 gap-3"><div class=md:col-span-2><label class="block text-sm mb-1" for=slug>Slug (optional)</label><div class="flex rounded-xl border overflow-hidden"><span class="px-3 py-2 text-slate-500 bg-slate-50">{{ public_host }}/</span><input id=slug name=slug type=text placeholder="(auto)" class="w-full p-2 outline-none"></div></div><div class=md:col-span-3><label class="block text-sm mb-1" for=dest_url>Destination URL</label><input id=dest_url name=dest_url type=url required placeholder="https://example.com/page" class="w-full rounded-xl border p-2"></div><div class="md:col-span-1 flex items-end"><button class="w-full rounded-xl px-4 py-2 bg-emerald-600 text-white">Save</button></div></form></div><div class="bg-white rounded-2xl shadow p-6 mt-6"><h2 class="text-lg font-semibold mb-4">Existing Links</h2>{% if rows %}<div class=overflow-x-auto><table class="min-w-full text-sm"><thead><tr class=text-left text-slate-500><th>Short</th><th>Destination</th><th>Hits</th><th>Created</th><th>Actions</th></tr></thead><tbody>{% for r in rows %}<tr class=border-t><td><a class=text-sky-700 href="https://{{ public_host }}/{{ r.slug }}" target=_blank>/{{ r.slug }}</a></td><td class=max-w-[420px] truncate><a href="{{ r.dest_url }}" target=_blank>{{ r.dest_url }}</a></td><td>{{ r.hits }}</td><td>{{ r.created_at }}</td><td><form method=post action="{{ url_for('delete', slug=r.slug) }}" onsubmit="return confirm('Delete /{{ r.slug }}?');"><button class="rounded-lg px-3 py-1 bg-rose-600 text-white">Delete</button></form></td></tr>{% endfor %}</tbody></table></div>{% else %}<p class=text-slate-500>No links yet.</p>{% endif %}</div>{% endblock %}"""

app.jinja_loader.mapping = {"base.html": BASE_HTML, "login.html": LOGIN_HTML, "dashboard.html": DASHBOARD_HTML}

@app.before_request
def enforce_https_when_proxied():
    if request.headers.get("X-Forwarded-Proto", "http") == "https":
        request.environ["wsgi.url_scheme"] = "https"

@app.get("/")
def home():
    return redirect(REDIRECT_HOME_TO, code=301)

@app.get("/admin")
def admin():
    if not is_logged_in():
        return render_template_string(LOGIN_HTML, title=APP_TITLE+" – Login", logged_in=False, year=datetime.utcnow().year, password_configured=bool(ADMIN_PASSWORD_BCRYPT))
    with Session(engine) as s:
        rows = s.execute(select(Link).order_by(Link.created_at.desc())).scalars().all()
    return render_template_string(DASHBOARD_HTML, title=APP_TITLE+" – Dashboard", logged_in=True, rows=rows, year=datetime.utcnow().year, public_host=PUBLIC_HOSTNAME)

@app.post("/admin/login")
def login():
    pwd = request.form.get("password", "")
    if check_password(pwd):
        session["admin"] = True
        flash("Welcome, Paul.", "success")
        return redirect(url_for("admin"))
    flash("Invalid password.", "error")
    return redirect(url_for("admin"))

@app.get("/admin/logout")
def logout():
    session.pop("admin", None)
    flash("Logged out.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/create")
def create():
    if not is_logged_in(): abort(403)
    slug = (request.form.get("slug") or "").strip()
    dest_url = normalize_url(request.form.get("dest_url") or "")
    if not dest_url:
        flash("Destination URL required.", "error"); return redirect(url_for("admin"))
    if slug and (slug in RESERVED_SLUGS or not SLUG_PATTERN.match(slug)):
        flash("Invalid slug.", "error"); return redirect(url_for("admin"))
    if not slug: slug = generate_slug(6)
    with Session(engine) as s:
        obj = s.get(Link, slug)
        if obj: obj.dest_url = dest_url
        else: s.add(Link(slug=slug, dest_url=dest_url, hits=0, created_at=datetime.utcnow()))
        s.commit()
    flash(f"Saved /{slug} → {dest_url}", "success"); return redirect(url_for("admin"))

@app.post("/admin/delete/<slug>")
def delete(slug):
    if not is_logged_in(): abort(403)
    if slug in RESERVED_SLUGS: flash("Cannot delete reserved path.", "error"); return redirect(url_for("admin"))
    with Session(engine) as s:
        obj = s.get(Link, slug)
        if obj: s.delete(obj); s.commit()
    flash(f"Deleted /{slug}", "success"); return redirect(url_for("admin"))

@app.get("/<path:slug>")
def go(slug):
    if slug in RESERVED_SLUGS: return abort(404)
    with Session(engine) as s:
        obj = s.get(Link, slug)
        if not obj: abort(404)
        obj.hits = (obj.hits or 0) + 1; dest = obj.dest_url; s.commit()
    return redirect(dest, code=302)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
```

