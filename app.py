# -*- coding: utf-8 -*-
"""
EvilCorp Support – intentionally vulnerable Flask CTF app.
Vulnerabilities (by design):
- CSRF on /account/change_password (uses GET and no token) – phishing support to hijack their account.
- Support chat renders HTML with |safe, enabling <img src=...> to trigger CSRF GET requests.
- Admin "Diagnostics > Template Preview" uses render_template_string with unsanitized input – SSTI to read flag.txt.
DO NOT deploy publicly. For local CTF labs only.
"""
import os
import datetime as dt
import random
import re
import threading
import time
import requests
import uuid
from functools import wraps

from flask import (
    Flask, render_template, render_template_string, request, redirect, url_for, flash, session, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------------------------------------------------------
# App & DB config
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-evilcorp')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///evilcorp.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Keep cookies default; CSRF intentionally omitted
db = SQLAlchemy(app)

# Global state for typing indicators (in production, use Redis/database)
typing_status = {}  # {user_id: {"support_typing": bool, "last_message_id": int}}

# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' | 'support' | 'admin'

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    sender = db.relationship('User', backref='messages')


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='low')  # low|medium|high|critical
    status = db.Column(db.String(20), default='open')
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def get_current_user():
    uid = session.get('user_id')
    if uid is None:
        return None
    return db.session.get(User, uid)

def login_required(roles=None):
    """roles: None (any authed), str, or iterable of roles"""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login', next=request.path))
            if roles is not None:
                allowed = {roles} if isinstance(roles, str) else set(roles)
                if user.role not in allowed:
                    abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.context_processor
def inject_globals():
    return {"current_user": get_current_user()}

def support_bot_response(user_message, user_id):
    """
    Automated support bot that responds to user messages and processes HTML content.
    This simulates a support agent clicking on links and viewing images.
    """
    with app.app_context():
        # Get the support user
        support_user = User.query.filter_by(username="support").first()
        if not support_user:
            print("Warning: No support user found!")  # Debug
            return
        
        print(f"Support bot processing message: {user_message[:100]}...")  # Debug
        
        # Show typing indicator
        typing_status[user_id] = typing_status.get(user_id, {})
        typing_status[user_id]["support_typing"] = True
        
        # Process any HTML content in the message (simulate viewing/clicking)
        process_html_content(user_message, support_user)
        
        # Simulate typing delay (human-like response time)
        typing_delay = random.uniform(3, 10)  # 3-10 seconds typing
        time.sleep(typing_delay)
        
        # Generate a response
        responses = [
            "Thanks for reaching out! I'll look into this issue right away.",
            "I'll read it later. Please, provide some links to your issue if you have any.",
            "I'm waiting for the img of your problem, man. Can you send a screenshot?",
            "Could you provide more details? Maybe some links or images that show the issue?",
            "I'll investigate this. Feel free to send any relevant links or screenshots.",
            "Let me check this out. If you have any supporting materials (images, links), please share them.",
            "Thanks! I'll review this shortly. Any additional links or visual aids would be helpful.",
            "Got it! Please include any images or links that might help me understand the issue better."
        ]
        
        response_content = random.choice(responses)
        
        # Send the response
        response_msg = Message(sender_id=support_user.id, content=response_content)
        db.session.add(response_msg)
        db.session.commit()
        
        # Update typing status and last message ID
        typing_status[user_id]["support_typing"] = False
        typing_status[user_id]["last_message_id"] = response_msg.id

def process_html_content(content, support_user):
    """
    Process HTML content in messages - this simulates the support user viewing images
    and clicking links, which triggers CSRF attacks.
    """
    # Find img tags and make requests to their src URLs
    img_pattern = r'<img[^>]+src=["\']([^"\']+)["\'][^>]*>'
    img_matches = re.findall(img_pattern, content, re.IGNORECASE)
    
    # Find direct links
    link_pattern = r'https?://[^\s<>"\']+(?:/account/change_password[^\s<>"\']*)?'
    link_matches = re.findall(link_pattern, content)
    
    all_urls = img_matches + link_matches
    
    for url in all_urls:
        try:
            # Check if this is a local URL that could be a CSRF attack
            if any(host in url for host in ['localhost', '127.0.0.1', '172.17.0.2', '0.0.0.0']) and 'change_password' in url:
                simulate_support_request(url, support_user)
        except Exception as e:
            print(f"Error processing URL {url}: {e}")  # Debug logging

def simulate_support_request(url, support_user):
    """
    Simulate the support user making an authenticated request to a URL.
    This handles both external requests and internal Flask route calls.
    """
    try:
        # For Docker/internal requests, make direct Flask test client request
        if any(host in url for host in ['127.0.0.1', 'localhost', '172.17.0.2', '0.0.0.0']):
            # Parse the URL to get the path and query parameters
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            
            if 'change_password' in parsed.path:
                # Extract parameters from query string
                params = parse_qs(parsed.query)
                new_password = params.get('new', [None])[0]
                confirm_password = params.get('confirm', [new_password])[0] if new_password else None
                
                if new_password and confirm_password:
                    # Directly change the support user's password (simulating successful CSRF)
                    print(f"CSRF Attack: Changing support password to '{new_password}'")  # Debug
                    support_user.set_password(new_password)
                    db.session.commit()
                    print(f"Support password changed successfully!")  # Debug
        else:
            # For external URLs, use requests with session cookie
            session_cookie = create_support_session_cookie(support_user.id)
            cookies = {'session': session_cookie}
            response = requests.get(url, cookies=cookies, timeout=5)
            print(f"External request to {url}, status: {response.status_code}")  # Debug
            
    except Exception as e:
        print(f"Error in simulate_support_request: {e}")  # Debug

def create_support_session_cookie(user_id):
    """
    Create a proper Flask session cookie for the support user.
    """
    try:
        # Use Flask's session interface to create a proper session cookie
        from flask.sessions import SecureCookieSessionInterface
        session_interface = SecureCookieSessionInterface()
        session_data = {'user_id': user_id}
        
        # Create a mock request context for serialization
        with app.test_request_context():
            serializer = session_interface.get_signing_serializer(app)
            return serializer.dumps(session_data)
    except Exception as e:
        print(f"Error creating session cookie: {e}")
        return "fallback_cookie"


# ----------------------------------------------------------------------------
# Routes – public & auth
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    if get_current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return redirect(url_for("register"))
        u = User(username=username, role='user')
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Registered! You can log in now.", "ok")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))
        session['user_id'] = user.id
        flash(f"Welcome, {user.username}!", "ok")
        next_url = request.args.get('next') or url_for('dashboard')
        return redirect(next_url)
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("index"))

# ----------------------------------------------------------------------------
# User dashboard – chat + profile
# ----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required()
def dashboard():
    user = get_current_user()
    # Show conversation between user and support
    support_user = User.query.filter_by(username="support").first()
    support_id = support_user.id if support_user else -1
    
    msgs = Message.query.filter(
        (Message.sender_id == user.id) | (Message.sender_id == support_id)
    ).order_by(Message.created_at.asc()).limit(50).all()
    
    return render_template("dashboard.html", messages=msgs)

@app.route("/message", methods=["POST"])
@login_required()
def send_message():
    # Debug headers and request info
    print(f"Request headers: {dict(request.headers)}")
    print(f"Request method: {request.method}")
    print(f"Is AJAX: {request.headers.get('X-Requested-With') == 'XMLHttpRequest'}")
    
    content = request.form.get("content") or ""
    content = content.strip()
    if not content:
        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            print("Returning AJAX error response")
            return jsonify({"error": "Message cannot be empty."}), 400
        flash("Message cannot be empty.", "error")
        return redirect(url_for("dashboard"))
    
    m = Message(sender_id=get_current_user().id, content=content)
    db.session.add(m)
    db.session.commit()
    
    # Trigger support bot response in a separate thread
    print(f"User {get_current_user().username} sent message: {content[:100]}... (Message ID: {m.id})")
    user_id = get_current_user().id
    threading.Thread(target=support_bot_response, args=(content, user_id), daemon=True).start()
    
    # Check if this is an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        print(f"Returning AJAX success response for message {m.id}")
        return jsonify({"success": True, "message_id": m.id})
    
    print("Returning redirect response")
    flash("Message sent to EvilCorp Support.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/api/messages")
@login_required()
def api_messages():
    """API endpoint to get new messages and typing status"""
    user = get_current_user()
    support_user = User.query.filter_by(username="support").first()
    support_id = support_user.id if support_user else -1
    
    # Get last message ID from client
    last_message_id = request.args.get('last_message_id', 0, type=int)
    
    # Get new messages since last_message_id
    new_messages = Message.query.filter(
        (Message.sender_id == user.id) | (Message.sender_id == support_id),
        Message.id > last_message_id
    ).order_by(Message.created_at.asc()).all()
    
    # Get typing status
    user_typing_status = typing_status.get(user.id, {})
    support_typing = user_typing_status.get("support_typing", False)
    
    # Convert messages to JSON
    messages_data = []
    for msg in new_messages:
        messages_data.append({
            'id': msg.id,
            'sender': msg.sender.username,
            'content': msg.content,
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'messages': messages_data,
        'support_typing': support_typing,
        'last_message_id': new_messages[-1].id if new_messages else last_message_id
    })

# Intentionally vulnerable CSRF endpoint: GET, no token, changes password of *whoever is logged in*
@app.route("/account/change_password", methods=["GET", "POST"])
@login_required()
def change_password_csrf():
    # Accept GET or POST, using common param names to make it easy to craft CSRF URLs
    new = request.values.get("new") or request.values.get("password") or request.values.get("pwd")
    confirm = request.values.get("confirm") or request.values.get("confirm_password") or new
    if not new or new != confirm:
        flash("Password change failed: missing or mismatch.", "error")
        return redirect(url_for("dashboard"))
    user = get_current_user()
    user.set_password(new)
    db.session.commit()
    flash("Password changed.", "ok")
    return redirect(url_for("dashboard"))

# ----------------------------------------------------------------------------
# Support perspective
# ----------------------------------------------------------------------------
@app.route("/support")
@login_required(roles="support")
def support_home():
    total = Ticket.query.count()
    recent = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
    return render_template("support_home.html", total=total, recent=recent)

@app.route("/support/chat")
@login_required(roles="support")
def support_chat():
    # Show all messages, render content as HTML (|safe in template)
    msgs = Message.query.order_by(Message.created_at.asc()).all()
    return render_template("support_chat.html", messages=msgs)

@app.route("/support/tickets")
@login_required(roles="support")
def support_tickets():
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    total = Ticket.query.count()
    last_page = (total + per_page - 1) // per_page
    tickets = Ticket.query.order_by(Ticket.id.asc()).offset((page - 1) * per_page).limit(per_page).all()
    return render_template("support_tickets.html",
                           tickets=tickets, page=page, last_page=last_page, total=total)



@app.route("/support/tickets/<ticket_uuid>")
@login_required(roles="support")
def ticket_detail(ticket_uuid: str):
    t = Ticket.query.filter_by(uuid=ticket_uuid).first()
    if not t:
        abort(404)
    return render_template("support_ticket_detail.html", ticket=t)

# ----------------------------------------------------------------------------
# Admin perspective
# ----------------------------------------------------------------------------
@app.route("/admin")
@login_required(roles="admin")
def admin_panel():
    return render_template("admin_panel.html", output=None, template=None)

@app.route("/admin/template", methods=["POST"])
@login_required(roles="admin")
def admin_template():
    template_code = (request.form.get("template") or "").strip()
    if not template_code:
        flash("Template code is required.", "error")
        return redirect(url_for("admin_panel"))
    # Intentionally vulnerable to SSTI (Server-Side Template Injection):
    try:
        output = render_template_string(template_code)
    except Exception as e:
        output = f"Template Error: {e}"
    return render_template("admin_panel.html", output=output, template=template_code)

# ----------------------------------------------------------------------------
# Error pages (simple)
# ----------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Not found"), 404

# ----------------------------------------------------------------------------
# Local run
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    # Ensure DB exists
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
