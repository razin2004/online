import os
import random
import smtplib
import string
import re
import secrets
import requests
from datetime import datetime, timedelta
from datetime import timezone


from flask import (
    Flask, render_template, request, redirect,
    session, flash,url_for
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///voting.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# -------------------------------------------------
# EMAIL CONFIG
# -------------------------------------------------

PROMAIL_API_KEY = "ee34a2c8-2dfa-44e8-862e-d7124cbadfb4"
PROMAIL_URL = "https://mailserver.automationlounge.com/api/v1/messages/send"

SMTP_EMAIL = "control.your.voting@gmail.com"
SMTP_PASSWORD = "sydpdtgkauovfiee"

USE_PROMAIL = True   # 🔁 switch here if needed


# -------------------------------------------------
# OTP EMAIL (ProMailer preferred, SMTP fallback)
# -------------------------------------------------
def send_otp_email(to, subject, html, text=None):
    """
    Used ONLY for OTP emails
    """

    # ---------- ProMailer ----------
    if USE_PROMAIL and PROMAIL_API_KEY:
        payload = {
            "to": to,
            "subject": subject,
            "html": html
        }

        if text:
            payload["text"] = text

        try:
            r = requests.post(
                PROMAIL_URL,
                headers={
                    "Authorization": f"Bearer {PROMAIL_API_KEY}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=10
            )

            print("ProMailer OTP:", r.status_code, r.text)

            if r.status_code == 200:
                return True

        except Exception as e:
            print("ProMailer OTP Exception:", e)

    # ---------- SMTP FALLBACK ----------
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            message = f"Subject: {subject}\n\n{text or html}"
            smtp.sendmail(SMTP_EMAIL, to, message)
            return True
    except Exception as e:
        print("SMTP OTP ERROR:", e)
        return False


# -------------------------------------------------
# SYSTEM EMAIL (Admin codes, notices)
# -------------------------------------------------
def send_vote_central_email(to_email, subject, body):
    """
    Used for NON-OTP emails
    """

    html = body.replace("\n", "<br>")

    # ---------- ProMailer ----------
    if USE_PROMAIL and PROMAIL_API_KEY:
        payload = {
            "to": to_email,
            "subject": subject,
            "html": f"""
            <div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.6">
                {html}
                <br><br>
                <hr>
                <small>VoteCentral · Secure · Verified · One Vote Per User</small>
            </div>
            """,
            "text": body
        }

        try:
            r = requests.post(
                PROMAIL_URL,
                headers={
                    "Authorization": f"Bearer {PROMAIL_API_KEY}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=10
            )

            print("ProMailer SYS:", r.status_code, r.text)

            if r.status_code == 200:
                return True

        except Exception as e:
            print("ProMailer SYS Exception:", e)

    # ---------- SMTP FALLBACK ----------
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            message = f"""From: VoteCentral <{SMTP_EMAIL}>
To: {to_email}
Subject: {subject}

{body}
"""
            smtp.sendmail(SMTP_EMAIL, to_email, message)
            return True
    except Exception as e:
        print("SMTP SYS ERROR:", e)
        return False


# 1. Get your API Key from https://www.promailer.xyz/
# 2. Add PROMAIL_API_KEY to Render Environment Variables




def generate_otp():
    return str(random.randint(100000, 999999))


def generate_admin_code():
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(8))



def generate_public_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def election_has_ended(election):
    if not election.end_time:
        return False
    return datetime.now() >= datetime.fromisoformat(election.end_time)

def store_new_otp(email, code, role, admin_id=None):

    # delete any existing OTP for this email + role
    OTPStore.query.filter_by(email=email, role=role).delete()

    otp_record = OTPStore(
        email=email,
        code=code,
        role=role,
        admin_id=admin_id,
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
    )

    db.session.add(otp_record)
    db.session.commit()

def voter_can_view_results(election):
    now = datetime.now()

    # PUBLIC — allow viewing anytime if admin enabled visibility
    if election.election_type == "public":
        return election.result_visible

    # PRIVATE — must wait until election ends
    if not election.end_time:
        return False

    if now < datetime.fromisoformat(election.end_time):
        return False

    return election.result_visible

def require_admin_login():
    if "admin_id" not in session or not session["admin_id"]:
        flash("Admin login required")
        return False
    return True


def require_voter_login():
    if "voter_logged" not in session or not session["voter_email"]:
        flash("Voter login required")
        return False
    return True

from werkzeug.utils import secure_filename

def save_uploaded_file(file):
    if not file or file.filename == "":
        return None

    filename = secure_filename(file.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(path)

    return filename

def clear_reset_session():
    session.pop("otp_reset_verified", None)
    session.pop("reset_email", None)
    session.pop("otp_context", None)
from datetime import timezone

def ensure_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def admin_register_otp_email(name, username, otp):
    return {
        "subject": "VoteCentral – Verify Your Admin Account",
        "body": f"""
Hello {name},

Your administrator account registration was initiated on VoteCentral.

Username: {username}

To complete your registration, please verify your email using the OTP below:

Verification OTP: {otp}

This OTP is valid for 5 minutes.
Do not share this code with anyone.

If you did not initiate this registration, please ignore this email.

Regards,
VoteCentral Security Team
Secure • Verified • One Vote Per User
"""
    }

def admin_reset_otp_email(name, username, otp):
    return {
        "subject": "VoteCentral – Password Reset Verification",
        "body": f"""
Hello {name},

A password reset was requested for your VoteCentral admin account.

Username: {username}

Please use the OTP below to proceed:

Password Reset OTP: {otp}

This OTP is valid for 5 minutes.
If you did not request this reset, please ignore this email.

Regards,
VoteCentral Support Team
Secure • Verified • One Vote Per User
"""
    }


def private_admin_code_email(admin_name, admin_code):
    return {
        "subject": "VoteCentral – Your Admin Account Is Ready",
        "body": f"""
Hello {admin_name},

Your admin account has been successfully created on VoteCentral.

As an administrator, you can now create and manage elections on the platform.
For conducting private elections, you will use the Admin Code provided below.

Admin Code: {admin_code}

This Admin Code is required for voters to access your private elections.
You may share this code only with trusted participants.

Please keep this code secure. Anyone with this code can attempt to access
private elections created under your account.

If you did not create this admin account, please contact support immediately.

Best regards,
VoteCentral Team
Secure • Verified • One Vote Per User
"""
    }

def voter_otp_email(otp):
    return {
        "subject": "VoteCentral – Voting OTP Verification",
        "body": f"""
Hello,

You are attempting to access a VoteCentral election.

Please use the One-Time Password (OTP) below to continue:

Voting OTP: {otp}

This OTP is valid for 5 minutes.
Do not share this code with anyone.

If you did not request this, you can safely ignore this email.

Regards,
VoteCentral Voting System
Secure • Verified • One Vote Per User
"""
    }
def resend_otp_email(otp, purpose):
    return {
        "subject": f"VoteCentral – {purpose} OTP",
        "body": f"""
Hello,

You requested a new OTP for {purpose.lower()}.

OTP Code: {otp}

This OTP is valid for 5 minutes.
For security reasons, never share this code.

Regards,
VoteCentral Security Team
Secure • Verified • One Vote Per User
"""
    }
def admin_username_recovery_email(name, username):
    return {
        "subject": "VoteCentral – Your Admin Username",
        "body": f"""
Hello {name},

You requested a reminder of your VoteCentral admin username.

Your username:
{username}

If you did not request this email, you can safely ignore it.
No changes were made to your account.

Regards,
VoteCentral Support Team
Secure • Verified • One Vote Per User
"""
    }

# -------------------------------------------------
# DATABASE MODELS
# -------------------------------------------------

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120))
    username = db.Column(db.String(80), unique=True)
    mobile = db.Column(db.String(20))
    whatsapp = db.Column(db.String(120))  
    email = db.Column(db.String(120), unique=True)

    password = db.Column(db.String(200))
    admin_code = db.Column(db.String(10), unique=True)

    elections = db.relationship("Election", backref="admin", cascade="all,delete")


class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"))
    name = db.Column(db.String(120))

    election_type = db.Column(db.String(20))  # public / private
    public_code = db.Column(db.String(20), nullable=True)

    start_time = db.Column(db.String(40), nullable=True)
    end_time = db.Column(db.String(40), nullable=True)

    result_visible = db.Column(db.Boolean, default=True)

    candidates = db.relationship("Candidate", backref="election", cascade="all,delete")
    votes = db.relationship("Vote", backref="election", cascade="all,delete")
    whitelist = db.relationship("VoterWhitelist", backref="election", cascade="all,delete")


class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("election.id"))

    name = db.Column(db.String(120))

    # NEW FIELDS
    party = db.Column(db.String(120), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    photo = db.Column(db.String(255), nullable=True)



class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    election_id = db.Column(db.Integer, db.ForeignKey("election.id"))
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidate.id"))

    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)   # 🔒 immutable
    updated_at = db.Column(db.DateTime, default=datetime.utcnow) 
    
class VoterWhitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("election.id"))
    email = db.Column(db.String(120))


class OTPStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(120))
    code = db.Column(db.String(10))
    role = db.Column(db.String(20))
    admin_id = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)



with app.app_context():
    db.create_all()

USERNAME_REGEX = re.compile(r'^(?!_)[a-z0-9_]{1,15}(?<!_)$')
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*[^A-Za-z0-9]).{8,}$')

# -------------------------------------------------
# HOME / LOGIN PAGE
# -------------------------------------------------

@app.route("/")
def index():
    return render_template("login.html")


# -------------------------------------------------
# ADMIN LOGIN
# -------------------------------------------------

@app.route("/admin/login", methods=["POST"])
def admin_login():

    username = request.form["username"].strip().lower()

    password = request.form["password"]

    admin = Admin.query.filter_by(username=username).first()

    if not admin or not check_password_hash(admin.password, password):
        flash("Invalid username or password", "admin_login_error")

        return redirect("/")

    session["admin_id"] = admin.id
    return redirect("/admin/dashboard")

from flask import jsonify

@app.route("/admin/check-username")
def check_username():
    username = (request.args.get("username") or "").strip().lower()

    if not USERNAME_REGEX.match(username):
        return jsonify(valid=False)

    exists = Admin.query.filter_by(username=username).first()
    return jsonify(
        valid=True,
        available=not bool(exists)
    )

# -------------------------------------------------
# ADMIN REGISTRATION (OTP FLOW)
# -------------------------------------------------

@app.route("/admin/register", methods=["POST"])
def admin_register():

    name     = request.form.get("name", "").strip()
    name = name.title()
    username = request.form.get("username", "").strip().lower()
    mobile   = request.form.get("mobile", "").strip()
    email    = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm", "")
    
    # ---- preserve entered values ----
    session["register_form"] = request.form
    if not USERNAME_REGEX.match(username):
        flash(
            "Username must be lowercase, letters/numbers/underscore only, "
            "max 15 characters, and not start or end with underscore",
            "admin_register_error"
        )
        return render_template(
            "login.html",
            open_panel="register",
            form=request.form
        )
    if not PASSWORD_REGEX.match(password):
        flash(
            "Password must be at least 8 characters, include one uppercase letter and one special character",
            "admin_register_error"
        )
        return render_template(
            "login.html",
            open_panel="register",
            form=request.form
        )

    # ---- password mismatch ----
    if password != confirm:
        flash("Passwords do not match", "admin_register_error")
        return render_template(
            "login.html",
            open_panel="register",
            form=request.form
        )

    # ---- username already exists ----
    existing = Admin.query.filter_by(username=username).first()
    if existing:
        flash("Username already exists", "admin_register_error")
        return render_template(
            "login.html",
            open_panel="register",
            form=request.form
        )
    # ---- email already registered ----
    if Admin.query.filter_by(email=email).first():
        flash("Email is already registered", "admin_register_error")

        # preserve form + stay in register panel
        return render_template(
            "login.html",
            open_panel="register",
            form=request.form
        )

    # ---- generate OTP ----
    otp = generate_otp()
    store_new_otp(email, otp, "admin_register")

    email_data = admin_register_otp_email(name, username, otp)
    send_vote_central_email(
        to_email=email,
        subject=email_data["subject"],
        body=email_data["body"]
    )




    # ---- prepare admin (not saved yet) ----
    session["pending_admin"] = {
        "name": name,
        "username": username,
        "mobile": mobile,
        "email": email,
        "password": generate_password_hash(password)
    }
    # remember OTP source — used by otp.html "Back" link
    session["otp_context"] = "admin_register"

    flash("OTP sent to your email — complete registration",
          "admin_register_success")

    return redirect("/verify-otp")
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    # OTP page only for admin registration
    if request.method == "GET":
        return render_template("otp.html", context="admin")

    otp = request.form["otp"]

    pending = session.get("pending_admin")
    if not pending:
        flash("Session expired — restart registration", "otp_error")
        return redirect("/?panel=register")

    email = pending["email"]

    record = OTPStore.query.filter_by(
        email=email,
        role="admin_register"
    ).order_by(OTPStore.id.desc()).first()

    # ---- invalid ----
    if not record or record.code != otp:
        flash("Invalid or expired OTP. Please try again.", "otp_error")
        return redirect("/verify-otp")

    # ---- expired ----
    if ensure_utc(record.expires_at) < datetime.now(timezone.utc):
        flash("OTP expired — request a new one", "otp_error")
        return redirect("/voter/otp")


    # ---- delete OTP ----
    db.session.delete(record)
    db.session.commit()

    # ---- create admin ----
    admin_code = generate_admin_code()
    # 🚫 SAFETY CHECK — prevent duplicate admin creation
    existing_admin = Admin.query.filter_by(email=pending["email"]).first()
    if existing_admin:
        # cleanup OTP + session to prevent loops
        OTPStore.query.filter_by(
            email=pending["email"],
            role="admin_register"
        ).delete()
        db.session.commit()

        session.pop("pending_admin", None)
        session.pop("otp_context", None)

        flash("This email is already registered. Please login.", "admin_login_error")
        return redirect("/?panel=login")

    new_admin = Admin(
        name=pending["name"],
        username=pending["username"],
        mobile=pending["mobile"],
        email=pending["email"],
        password=pending["password"],
        admin_code=admin_code
    )

    db.session.add(new_admin)
    db.session.commit()

    email_data = private_admin_code_email(
    pending["name"],
    admin_code
)

    send_vote_central_email(
        to_email=email,
        subject=email_data["subject"],
        body=email_data["body"]
    )


    # cleanup
    session.pop("pending_admin", None)
    session.pop("otp_context", None)

    flash("Registration successful — you may login now", "otp_success")
    return redirect("/?panel=login")

# -------------------------------------------------
# ADMIN FORGOT PASSWORD — REQUEST RESET OTP
# -------------------------------------------------
@app.route("/admin/forgot-username", methods=["POST"])
def admin_forgot_username():

    email = request.form["email"].strip().lower()
    admin = Admin.query.filter_by(email=email).first()

    # 🔒 Do not reveal existence
    if admin:
        email_data = {
            "subject": "VoteCentral – Your Admin Username",
            "body": f"""
Hello {admin.name},

You requested a reminder of your VoteCentral admin username.

Your username:
{admin.username}

If you did not request this email, you can safely ignore it.

Regards,
VoteCentral Support Team
Secure • Verified • One Vote Per User
"""
        }

        send_vote_central_email(
            to_email=admin.email,
            subject=email_data["subject"],
            body=email_data["body"]
        )

    flash(
        "If the email is registered, recovery instructions have been sent.",
        "admin_login_success"
    )
    return redirect("/")

@app.route("/admin/forgot-password", methods=["POST"])
def admin_forgot_password():

    email = request.form["email"].strip().lower()

    admin = Admin.query.filter_by(email=email).first()

    # Security: do NOT reveal whether email exists
    # Always show success response

    otp = generate_otp()

    if admin:

        # delete previous reset OTPs
        OTPStore.query.filter_by(
            email=email,
            role="admin_reset"
        ).delete()

        store_new_otp(email, otp, "admin_reset")

        email_data = admin_reset_otp_email(admin.name, admin.username, otp)
        send_vote_central_email(
            to_email=admin.email,
            subject=email_data["subject"],
            body=email_data["body"]
        )

        session["reset_email"] = email

    session["otp_context"] = "admin_reset"

    flash("If the email is registered, an OTP has been sent.", "otp_success")
    return redirect("/verify-otp?context=reset")
# -------------------------------------------------
# ADMIN PASSWORD RESET — OTP VERIFICATION
# -------------------------------------------------

@app.route("/admin/reset-verify", methods=["POST"])
def admin_reset_verify():

    email = session.get("reset_email")

    if not email:
        flash("Session expired — restart reset process", "otp_error")
        return redirect("/")

    otp = request.form["otp"]

    record = OTPStore.query.filter_by(
        email=email,
        role="admin_reset"
    ).order_by(OTPStore.id.desc()).first()

    if not record or record.code != otp:
        flash("Invalid or expired OTP. Please try again.", "otp_error")
        return redirect("/verify-otp?context=reset")

    if ensure_utc(record.expires_at) < datetime.now(timezone.utc):
        flash("OTP expired — request new reset link", "otp_error")
        return redirect("/")

    # delete otp after verification
    db.session.delete(record)
    db.session.commit()

    session["otp_reset_verified"] = True

    flash("OTP verified — create your new password", "otp_success")
    return redirect("/?panel=reset")
# -------------------------------------------------
# ADMIN RESET — UPDATE PASSWORD
# -------------------------------------------------
@app.route("/admin/reset-password", methods=["POST"])
def admin_reset_password():

    if not session.get("otp_reset_verified"):
        flash("OTP verification required", "otp_error")
        return redirect("/")

    email = session.get("reset_email")
    admin = Admin.query.filter_by(email=email).first()

    if not admin:
        flash("Account not found", "otp_error")
        return redirect("/")

    # ✅ DEFINE VARIABLES FIRST
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm", "")

    # ---- password strength ----
    if not PASSWORD_REGEX.match(password):
        flash(
            "Password must be at least 8 characters, include one uppercase letter and one special character",
            "otp_error"
        )
        return redirect("/?panel=reset")

    # ---- match check ----
    if password != confirm:
        flash("Passwords do not match", "otp_error")
        return redirect("/?panel=reset")

    admin.password = generate_password_hash(password)
    db.session.commit()

    # ✅ CLEANUP SESSION
    session.pop("otp_reset_verified", None)
    session.pop("reset_email", None)
    session.pop("otp_context", None)

    flash("Password updated successfully. Please login.", "admin_login_success")
    return redirect("/")

from flask import jsonify

@app.route("/admin/profile/update", methods=["POST"])
def admin_profile_update():

    if not require_admin_login():
        return jsonify(success=False, message="Unauthorized"), 403

    admin = Admin.query.get(session["admin_id"])
    if not admin:
        return jsonify(success=False, message="Admin not found"), 404

    data = request.get_json() or {}

    name = (data.get("name") or "").strip().title()
    username = (data.get("username") or "").strip().lower()

    mobile = (data.get("mobile") or "").strip()
    whatsapp = (data.get("whatsapp") or "").strip()
    if not USERNAME_REGEX.match(username):
        return jsonify(success=False, message="Invalid username format")

    # ---- basic validation ----
    if not name or not username:
        return jsonify(success=False, message="Name and username are required")

    # ---- username uniqueness ----
    existing = Admin.query.filter(
        Admin.username == username,
        Admin.id != admin.id
    ).first()

    if existing:
        return jsonify(success=False, message="Username already in use")

    # ---- update fields ----
    admin.name = name
    admin.username = username
    admin.mobile = mobile or None
    admin.whatsapp = whatsapp or None

    db.session.commit()

    return jsonify(success=True)
@app.route("/admin/check-email")
def check_email():
    email = (request.args.get("email") or "").strip().lower()

    if "@" not in email or "." not in email:
        return jsonify(valid=False)

    exists = Admin.query.filter_by(email=email).first()
    return jsonify(
        valid=True,
        available=not bool(exists)
    )

@app.route("/admin/reset-resend")
def admin_reset_resend():

    email = session.get("reset_email")
    if not email:
        flash("Session expired — restart reset process", "otp_error")
        return redirect("/")

    otp = generate_otp()
    store_new_otp(email, otp, "admin_reset")

    admin = Admin.query.filter_by(email=email).first()

    email_data = admin_reset_otp_email(
        admin.name if admin else "Admin",
        admin.username if admin else "unknown",
        otp
    )

    send_vote_central_email(
        to_email=email,
        subject=email_data["subject"],
        body=email_data["body"]
    )


    flash("New OTP sent to your email", "otp_success")
    return redirect("/verify-otp?context=reset")

@app.route("/admin/reset-cancel")
def admin_reset_cancel():

    # Explicitly invalidate reset session
    session.pop("otp_reset_verified", None)
    session.pop("reset_email", None)
    session.pop("otp_context", None)

    flash(
        "Password reset cancelled. No changes were made.",
        "admin_login_success"
    )
    return redirect("/")

@app.route("/voter/resend-otp")
def voter_resend_otp():

    email = session.get("voter_email")
    if not email:
        flash("Session expired — start login again", "otp_error")
        return redirect("/")

    role = "voter_private" if "voter_admin_id" in session else "voter_public"

    otp = generate_otp()
    store_new_otp(email, otp, role)

    email_data = voter_otp_email(otp)
    send_vote_central_email(
        to_email=email,
        subject=email_data["subject"],
        body=email_data["body"]
    )


    flash("A new OTP has been sent", "otp_success")
    return redirect("/voter/otp")
@app.route("/admin/register-resend")
def admin_register_resend():

    pending = session.get("pending_admin")
    if not pending:
        flash("Session expired — register again", "otp_error")
        return redirect("/")

    email = pending["email"]

    otp = generate_otp()
    store_new_otp(email, otp, "admin_register")

    email_data = resend_otp_email(otp, "Admin Registration")
    send_vote_central_email(
        to_email=email,
        subject=email_data["subject"],
        body=email_data["body"]
    )


    flash("New OTP sent to your email", "otp_success")
    return redirect("/verify-otp")

# -------------------------------------------------
# VOTER LOGIN — PUBLIC
# -------------------------------------------------

@app.route("/voter/login/public", methods=["POST"])
def voter_public_login():

    email = request.form["email"].strip().lower()

    if "@" not in email:
        flash("Enter a valid email address", "voter_public_error")
        return render_template("login.html", open_panel="voter")

    otp = generate_otp()
    store_new_otp(email, otp, "voter_public")

    email_data = voter_otp_email(otp)
    send_vote_central_email(
        to_email=email,
        subject=email_data["subject"],
        body=email_data["body"]
    )


    session["voter_email"] = email

    flash("OTP sent to your email", "voter_public_success")
    return redirect("/voter/otp")



# -------------------------------------------------
# VOTER LOGIN — PRIVATE
# -------------------------------------------------
@app.route("/voter/login/private", methods=["POST"])
def voter_private_login():

    admin_code = request.form["admin_code"].strip()
    email = request.form["email"].strip().lower()

    admin = Admin.query.filter_by(admin_code=admin_code).first()

    if not admin:
        flash("Admin code not found", "voter_private_error")
        return render_template("login.html", open_panel="voter")

    if "@" not in email:
        flash("Enter a valid email address", "voter_private_error")
        return render_template("login.html", open_panel="voter")

    otp = generate_otp()
    store_new_otp(email, otp, "voter_private", admin.id)

    email_data = voter_otp_email(otp)
    send_vote_central_email(
        to_email=email,
        subject=email_data["subject"],
        body=email_data["body"]
    )


    session["voter_email"] = email
    session["voter_admin_id"] = admin.id

    flash("OTP sent to your email", "voter_private_success")
    return redirect("/voter/otp")



# -------------------------------------------------
# VERIFY VOTER OTP
# -------------------------------------------------

@app.route("/voter/otp", methods=["GET", "POST"])
def voter_verify():

    # only clear reset context if this is NOT a reset flow
    if session.get("otp_context") != "admin_reset":
        session.pop("otp_reset_verified", None)
        session.pop("reset_email", None)
        session.pop("otp_context", None)


    if request.method == "GET":
        return render_template("otp.html",context="voter")

    otp = request.form["otp"]
    email = session["voter_email"]

    record = OTPStore.query.filter_by(
        email=email,
        role="voter_public" if "voter_admin_id" not in session else "voter_private"
    ).order_by(OTPStore.id.desc()).first()

    if not record or record.code != otp:
        flash("Invalid or expired OTP. Please try again.", "otp_error")

        return redirect("/voter/otp")

    if ensure_utc(record.expires_at) < datetime.now(timezone.utc):
        flash("OTP expired — request a new OTP", "otp_error")
        return redirect("/")
    # OTP verified — delete it permanently
    db.session.delete(record)
    db.session.commit()

    if not record:
        flash("Invalid or expired OTP. Please try again.", "otp_error")

        return redirect("/voter/otp")

    session["voter_logged"] = True
    return redirect("/voter/dashboard")


# -------------------------------------------------
# VOTER DASHBOARD
# -------------------------------------------------
# -------------------------------------------------
# VOTER DASHBOARD
# -------------------------------------------------
@app.route("/voter/dashboard")
def voter_dashboard():

    if not require_voter_login():
        return redirect("/")

    if "admin_id" in session:
        flash("Admins cannot access voter panel")
        return redirect("/admin/dashboard")

    email = session["voter_email"]
    q = request.args.get("q", "").strip().lower()

    voted_set = {
        v.election_id
        for v in Vote.query.filter_by(email=email).all()
    }

    admin = None   # ✅ IMPORTANT

    # ---- PUBLIC LOGIN ----
    if "voter_admin_id" not in session:
        elections = Election.query.filter_by(
            election_type="public"
        ).all()

    # ---- PRIVATE LOGIN ----
    else:
        admin_id = session["voter_admin_id"]
        admin = db.session.get(Admin, admin_id)   # ✅ LOAD ADMIN
        elections = Election.query.filter_by(
            admin_id=admin_id
        ).all()

    election_list = []

    for e in elections:

        if q:
            text = (e.name or "").lower()
            code = (e.public_code or "").lower()
            if q not in text and q not in code:
                continue

        total_votes = Vote.query.filter_by(
            election_id=e.id
        ).count()

        candidate_count = Candidate.query.filter_by(
            election_id=e.id
        ).count()

        allowed = True
        if e.election_type == "private":
            allowed = VoterWhitelist.query.filter_by(
                election_id=e.id,
                email=email
            ).first() is not None

        election_list.append({
            "id": e.id,
            "name": e.name,
            "type": e.election_type,
            "start_time": e.start_time,
            "end_time": e.end_time,
            "total_votes": total_votes,
            "candidate_count": candidate_count,
            "voted": e.id in voted_set,
            "allowed": allowed,
            "public_code": e.public_code
        })

    return render_template(
        "voter_dashboard.html",
        elections=election_list,
        email=email,
        admin=admin,        # ✅ PASS ADMIN (or None)
        search_query=q
    )


@app.route("/voter/results")
def voter_results_list():

    if not require_voter_login():
        return redirect("/")

    email = session["voter_email"]

    # ---- PUBLIC LOGIN ----
    if "voter_admin_id" not in session:

        elections = Election.query.filter_by(election_type="public").all()

    # ---- PRIVATE LOGIN ----
    else:
        admin_id = session["voter_admin_id"]

        elections = Election.query.filter_by(admin_id=admin_id).all()

    result_rows = []

    now = datetime.now()

    for e in elections:

        # PRIVATE — voter must be whitelisted
        if e.election_type == "private":
            allowed = VoterWhitelist.query.filter_by(
                election_id=e.id,
                email=email
            ).first()
            if not allowed:
                continue

        total_votes = Vote.query.filter_by(election_id=e.id).count()

        start = datetime.fromisoformat(e.start_time) if e.start_time else None
        end   = datetime.fromisoformat(e.end_time)   if e.end_time else None

        now = datetime.now()

        is_upcoming = False
        is_running  = False
        is_ended    = False

        if start and end:
            if now < start:
                is_upcoming = True
            elif start <= now <= end:
                is_running = True
            else:
                is_ended = True
        else:
            # elections without schedule are treated as running
            is_running = True

        can_view = voter_can_view_results(e)

        result_rows.append({
            "id": e.id,
            "name": e.name,
            "type": e.election_type,
            "total_votes": total_votes,

            "upcoming": is_upcoming,
            "running": is_running,
            "ended": is_ended,

            "visible": e.result_visible,
            "can_view": can_view,
            "public_code": e.public_code
        })

    return render_template(
        "voter_results.html",
        elections=result_rows,
        email=email
    )

@app.route("/voter/results/<eid>")
def voter_result_detail(eid):

    if not require_voter_login():
        return redirect("/")

    email = session["voter_email"]
    election = Election.query.get_or_404(eid)

    # unified rule — end time + visibility together
    if not voter_can_view_results(election):
        flash("Results are not available for this election")
        return redirect("/voter/results")

    # PRIVATE ACCESS CHECK
    if election.election_type == "private":
        allowed = VoterWhitelist.query.filter_by(
            election_id=election.id,
            email=email
        ).first()
        if not allowed:
            flash("You are not allowed to view this election result")
            return redirect("/voter/results")

    candidates = Candidate.query.filter_by(election_id=election.id).all()

    # 1. Fetch and Count
    result = []
    max_votes = 0
    for c in candidates:
        count = Vote.query.filter_by(candidate_id=c.id).count()
        max_votes = max(max_votes, count)
        result.append({
            "name": c.name,
            "count": count,
            "photo": c.photo,
            "party": getattr(c, 'party', 'Independent') # Safe fallback
        })

    # 2. SORT BY VOTES (Highest first)
    result = sorted(result, key=lambda x: x['count'], reverse=True)

    # 3. Mark Winner/Leader
    for r in result:
        r["winner"] = (r["count"] == max_votes and max_votes > 0)

    # 4. Calculate Whitelist Stats
    total_whitelisted = VoterWhitelist.query.filter_by(election_id=election.id).count()
    voted_count = Vote.query.filter_by(election_id=election.id).count()
    not_voted_count = max(0, total_whitelisted - voted_count) if election.election_type == 'private' else 0
    total_votes = Vote.query.filter_by(election_id=election.id).count()
    # 5. Premium Date Formatting
    def format_date(date_str):
        if not date_str: return "N/A"
        try:
            dt = datetime.fromisoformat(date_str)
            return dt.strftime("%b %d, %Y • %I:%M %p") # e.g. Jan 20, 2026 • 04:30 PM
        except: return date_str

    return render_template(
        "voter_result_detail.html", # or admin_result_detail.html
        election=election,
        result=result,
        total_votes=total_votes,
        total_whitelisted=total_whitelisted,
        not_voted_count=not_voted_count,
        start_fmt=format_date(election.start_time),
        end_fmt=format_date(election.end_time)
    )

from datetime import datetime

@app.route("/election/<eid>")
def view_election(eid):

    if not require_voter_login():
        return redirect("/")

    email = session["voter_email"]
    election = Election.query.get_or_404(eid)
    now = datetime.now(timezone.utc)

    # 🚫 Block viewing private elections of other admins
    if election.election_type == "private" and "voter_admin_id" in session:
        if election.admin_id != session["voter_admin_id"]:
            flash("You are not allowed to access this election")
            return redirect("/voter/dashboard")

    # count total votes
    total_votes = Vote.query.filter_by(election_id=eid).count()

    # PRIVATE — whitelist enforcement
    if election.election_type == "private":
        allowed = VoterWhitelist.query.filter_by(
            election_id=eid,
            email=email
        ).first()

        if not allowed:
            flash("You are not allowed to view this election")
            return redirect("/voter/dashboard")

    candidates = Candidate.query.filter_by(election_id=eid).all()

    voted = Vote.query.filter_by(
        election_id=eid,
        email=email
    ).first()

    # -----------------------------------
    # 🗳️ CHANGE-VOTE WINDOW (45s HARD LIMIT)
    # -----------------------------------
    LOCK_SECONDS = 45
    can_change = False
    remaining_seconds = 0

    if voted:
        elapsed = (now - ensure_utc(voted.created_at)).total_seconds()

        if elapsed < LOCK_SECONDS:
            can_change = True
            remaining_seconds = int(LOCK_SECONDS - elapsed)

    # -----------------------------------
    # ⏱️ ELECTION STATE (FOR UI)
    # -----------------------------------
    start_time = datetime.fromisoformat(election.start_time) if election.start_time else None
    end_time   = datetime.fromisoformat(election.end_time) if election.end_time else None

    has_started = start_time and now >= ensure_utc(start_time)
    has_ended   = end_time and now > ensure_utc(end_time)


    return render_template(
        "single_election.html",
        election=election,
        candidates=candidates,
        total_votes=total_votes,
        email=email,
        voted=voted,
        can_change=can_change,
        remaining_seconds=remaining_seconds,
        lock_seconds=LOCK_SECONDS,
        has_started=has_started,
        has_ended=has_ended
    )



# -------------------------------------------------
# CAST VOTE
# -------------------------------------------------

@app.route("/vote", methods=["POST"])
def cast_vote():

    email = request.form["email"]
    election_id = request.form["election_id"]
    candidate_id = request.form["candidate_id"]

    if request.form.get("confirm_flag") != "yes":
        flash("Vote not submitted — confirmation required")
        return redirect("/voter/dashboard")

    election = Election.query.get_or_404(election_id)

    # ---- schedule checks ----
    if election.start_time and datetime.now() < datetime.fromisoformat(election.start_time):
        flash("Election has not started yet")
        return redirect("/voter/dashboard")

    if election.end_time and datetime.now() > datetime.fromisoformat(election.end_time):
        flash("Election has ended")
        return redirect("/voter/dashboard")

    # ---- whitelist ----
    if election.election_type == "private":
        allowed = VoterWhitelist.query.filter_by(
            election_id=election_id,
            email=email
        ).first()
        if not allowed:
            flash("You are not allowed to vote in this election")
            return redirect("/voter/dashboard")

    existing_vote = Vote.query.filter_by(
        election_id=election_id,
        email=email
    ).first()

    # -----------------------------
    # FIRST VOTE
    # -----------------------------
    if not existing_vote:
        db.session.add(Vote(
            election_id=election_id,
            candidate_id=candidate_id,
            email=email,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        ))
        db.session.commit()

        flash("Vote recorded successfully. You may change it for 45 seconds.")
        return redirect(f"/election/{election_id}")

    # -----------------------------
    # MODIFY WITHIN 45 SECONDS
    # -----------------------------
    elapsed = (
        datetime.now(timezone.utc) - ensure_utc(existing_vote.created_at)
    ).total_seconds()

    if elapsed <= 45:
        existing_vote.candidate_id = candidate_id
        existing_vote.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        flash(f"Vote updated. {int(45-elapsed)} seconds remaining.")
        return redirect(f"/election/{election_id}")

    # -----------------------------
    # LOCKED
    # -----------------------------
    flash("Modification window closed. Your vote is already cast.")
    return redirect(f"/election/{election_id}")



# -------------------------------------------------
# ADMIN DASHBOARD
# -------------------------------------------------

@app.route("/admin/dashboard")
def admin_dashboard():

    if not require_admin_login():
        return redirect("/")

    # block voter session
    if "voter_logged" in session:
        flash("Voters cannot access admin panel")
        return redirect("/voter/dashboard")

    admin = db.session.get(Admin, session.get("admin_id"))

    elections = Election.query.filter_by(admin_id=admin.id).all()
    from datetime import datetime

    for e in elections:

        total_votes = Vote.query.filter_by(election_id=e.id).count()
        e.total_votes = total_votes

        # ----- TIME FLAGS (safe boolean states) -----
        e.is_upcoming = False
        e.is_running  = False
        e.is_ended    = False

        if e.start_time and e.end_time:
            start = datetime.fromisoformat(e.start_time)
            end   = datetime.fromisoformat(e.end_time)
            now   = datetime.now()

            if now < start:
                e.is_upcoming = True
            elif start <= now <= end:
                e.is_running = True
            else:
                e.is_ended = True


        results = []

        for c in e.candidates:
            vote_count = Vote.query.filter_by(candidate_id=c.id).count()

            # ===== RULE =====
            # PUBLIC → show candidate votes always
            # PRIVATE → hide until election ends
            if e.election_type == "private" and not election_has_ended(e):
                display_count = "—"
            else:
                display_count = vote_count

            results.append({
                "id": c.id,
                "candidate": c.name,
                "party": c.party,
                "description": c.description,
                "photo": f"/static/uploads/{c.photo}" if c.photo else None,
                "count": display_count,
                "raw_count": vote_count
            })


        # winner calculation only when votes are visible
        visible_counts = [
            r["raw_count"]
            for r in results
            if isinstance(r["count"], int)
        ]

        if visible_counts:
            max_votes = max(visible_counts)
            for r in results:
                r["is_winner"] = (r["raw_count"] == max_votes and max_votes > 0)
        else:
            for r in results:
                r["is_winner"] = False

        e.results = results


    return render_template(
        "admin_dashboard.html",
        admin=admin,          # ← REQUIRED
        elections=elections,
        datetime=datetime
    )

@app.route("/admin/api/candidates/<eid>")
def api_candidates(eid):

    if not require_admin_login():
        return {"error": "not authorized"}, 403

    election = Election.query.get_or_404(eid)

    data = []
    for c in election.candidates:
        data.append({
            "id": c.id,
            "name": c.name,
            "party": c.party or "",
            "photo": c.photo,
            "description": c.description or "",
            "votes": Vote.query.filter_by(candidate_id=c.id).count()
        })

    return {"candidates": data}

@app.route("/admin/api/whitelist/<eid>")
def api_whitelist(eid):

    if not require_admin_login():
        return {"error": "not authorized"}, 403

    election = Election.query.get_or_404(eid)

    entries = VoterWhitelist.query.filter_by(election_id=election.id).all()

    data = [
        {
            "id": w.id,
            "email": w.email
        }
        for w in entries
    ]

    return {"whitelist": data}
@app.route("/admin/results")
def admin_results_page():
    if not require_admin_login():
        return redirect("/")

    admin = Admin.query.get(session["admin_id"])
    elections = Election.query.filter_by(admin_id=admin.id).all()

    result_list = []
    now = datetime.now()

    for e in elections:
        total_votes = Vote.query.filter_by(election_id=e.id).count()
        
        # Determine timing
        ended = False
        if e.end_time:
            # Handle both string and datetime objects if necessary
            end_dt = datetime.fromisoformat(e.end_time) if isinstance(e.end_time, str) else e.end_time
            ended = now >= end_dt

        # Determine accessibility and reason
        can_open = False
        reason = ""

        if not e.result_visible:
            reason = "This election is currently set to 'Hidden' by Admin settings."
        elif e.election_type == 'private' and not ended:
            reason = f"Private election results remain locked until the end time ({e.end_time})."
        else:
            can_open = True

        result_list.append({
            "id": e.id,
            "name": e.name,
            "type": e.election_type,
            "total_votes": total_votes,
            "ended": ended,
            "visible": e.result_visible,
            "can_open": can_open,
            "reason": reason
        })

    return render_template("admin_results.html", elections=result_list, admin=admin)

@app.route("/admin/results/<eid>")
def admin_result_detail(eid):

    if not require_admin_login():
        return redirect("/")

    election = Election.query.get_or_404(eid)

    now = datetime.now()
    ended = False
    if election.end_time:
        ended = now >= datetime.fromisoformat(election.end_time)

    # PRIVATE — block viewing before end time
    if election.election_type == "private" and not ended:
        flash("Private election results unlock only end time")
        return redirect("/admin/results")

    candidates = Candidate.query.filter_by(election_id=election.id).all()
# 1. Fetch and Count
    result = []
    max_votes = 0
    for c in candidates:
        count = Vote.query.filter_by(candidate_id=c.id).count()
        max_votes = max(max_votes, count)
        result.append({
            "name": c.name,
            "count": count,
            "photo": c.photo,
            "party": getattr(c, 'party', 'Independent') # Safe fallback
        })

    # 2. SORT BY VOTES (Highest first)
    result = sorted(result, key=lambda x: x['count'], reverse=True)

    # 3. Mark Winner/Leader
    for r in result:
        r["winner"] = (r["count"] == max_votes and max_votes > 0)

    # 4. Calculate Whitelist Stats
    total_whitelisted = VoterWhitelist.query.filter_by(election_id=election.id).count()
    voted_count = Vote.query.filter_by(election_id=election.id).count()
    not_voted_count = max(0, total_whitelisted - voted_count) if election.election_type == 'private' else 0
    total_votes = Vote.query.filter_by(election_id=election.id).count()
    # 5. Premium Date Formatting
    def format_date(date_str):
        if not date_str: return "N/A"
        try:
            dt = datetime.fromisoformat(date_str)
            return dt.strftime("%b %d, %Y • %I:%M %p") # e.g. Jan 20, 2026 • 04:30 PM
        except: return date_str

    return render_template(
        "admin_result_detail.html", # or admin_result_detail.html
        election=election,
        result=result,
        total_votes=total_votes,
        total_whitelisted=total_whitelisted,
        not_voted_count=not_voted_count,
        start_fmt=format_date(election.start_time),
        end_fmt=format_date(election.end_time)
    )


# -------------------------------------------------
# CREATE ELECTION
# -------------------------------------------------
from datetime import datetime
@app.route("/admin/create-election", methods=["POST"])
def create_election():

    if not require_admin_login():
        return redirect("/")

    etype = request.form["type"]
    name  = request.form["name"].strip()

    start_raw = request.form.get("start_time") or None
    end_raw   = request.form.get("end_time") or None

    try:
        start = datetime.fromisoformat(start_raw) if start_raw else None
        end   = datetime.fromisoformat(end_raw) if end_raw else None
    except ValueError:
        flash("Invalid date or time format. Please select a valid date and time.")
        return redirect("/admin/dashboard?open=create")


    now = datetime.now()

    # ---------------- VALIDATIONS ----------------

    # ❌ Start time cannot be before creation time
    if start and start < now:
        flash("Start time cannot be in the past.")
        return redirect("/admin/dashboard?open=create")

    # ❌ End time must be after current time
    if end and end <= now:
        flash("End time must be after the current time.")
        return redirect("/admin/dashboard?open=create")

    # ❌ Start must be before end
    if start and end and start >= end:
        flash("Start time must be before the end time.")
        return redirect("/admin/dashboard?open=create")

    # ❌ Private election requires both times
    if etype == "private" and (not start or not end):
        flash("Private elections must have both start and end time.")
        return redirect("/admin/dashboard?open=create")


    # ---------------- CREATE ----------------

    election = Election(
        admin_id=session["admin_id"],
        name=name,
        election_type=etype,
        start_time=start.isoformat() if start else None,
        end_time=end.isoformat() if end else None
    )

    if etype == "public":
        election.public_code = generate_public_code()

    db.session.add(election)
    db.session.commit()

    flash(f"Election '{name}' created successfully.")
    return redirect(
        url_for(
            "admin_dashboard",
            open="candidates",
            eid=election.id,
            name=election.name
        )
    )




# -------------------------------------------------
# ADD CANDIDATE
# -------------------------------------------------
@app.route("/admin/add-candidate", methods=["POST"])
def add_candidate():

    election = Election.query.get_or_404(request.form["election_id"])

    now = datetime.now(timezone.utc)

    start = (
        ensure_utc(datetime.fromisoformat(election.start_time))
        if election.start_time else None
    )
    end = (
        ensure_utc(datetime.fromisoformat(election.end_time))
        if election.end_time else None
    )

    # 🔴 RULE 1: Election ended → never allow
    if end and now > end:
        flash("Cannot add candidates — the election has already ended.")
        return redirect("/admin/dashboard")

    # 🟡 RULE 2: Election running + votes exist → block
    if start and start <= now:
        vote_exists = Vote.query.filter_by(
            election_id=election.id
        ).first()

        if vote_exists:
            flash(
                "Cannot add candidates — voting has already started "
                "and votes have been cast."
            )
            return redirect("/admin/dashboard")

    # ✅ RULE 3: Allowed (not started OR running with zero votes)
    uploaded = request.files.get("photo")

    photo = None
    if uploaded and uploaded.filename:
        photo = save_uploaded_file(uploaded)
    else:
        photo = "default-candidate.jpg"


    candidate = Candidate(
        election_id=election.id,
        name=request.form["name"].strip(),
        party=request.form.get("party"),
        description=request.form.get("description"),
        photo=photo
    )

    db.session.add(candidate)
    db.session.commit()

    # Context-aware success message
    if start and start <= now:
        flash("Candidate added successfully (no votes had been cast).")
    else:
        flash("Candidate added successfully before the election started.")

    return redirect(request.referrer or "/admin/dashboard")



# -------------------------------------------------
# EDIT CANDIDATE NAME
# -------------------------------------------------

@app.route("/admin/candidate/edit", methods=["POST"])
def edit_candidate():

    candidate = Candidate.query.get(request.form["candidate_id"])

    if not candidate:
        flash("Candidate not found")
        return redirect("/admin/dashboard")

    election = Election.query.get(candidate.election_id)

    if election_has_ended(election):
        flash("Cannot edit candidate — election already ended")
        return redirect("/admin/dashboard")

    candidate.name = request.form["name"]
    db.session.commit()

    flash("Candidate updated")
    return redirect(request.referrer or "/admin/dashboard")




# -------------------------------------------------
# DELETE CANDIDATE (only if no votes)
# -------------------------------------------------
@app.route("/admin/candidate/delete/<cid>")
def delete_candidate(cid):

    candidate = db.session.get(Candidate, cid)
    if not candidate:
        flash("Candidate not found.")
        return redirect(request.referrer or "/admin/dashboard")

    election = db.session.get(Election, candidate.election_id)
    if not election:
        flash("Election not found.")
        return redirect(request.referrer or "/admin/dashboard")

    now = datetime.now(timezone.utc)

    start = (
        ensure_utc(datetime.fromisoformat(election.start_time))
        if election.start_time else None
    )
    end = (
        ensure_utc(datetime.fromisoformat(election.end_time))
        if election.end_time else None
    )

    # ❌ RULE 1: Election ended → never allow
    if end and now > end:
        flash("Cannot delete candidate — the election has already ended.")
        return redirect(request.referrer or "/admin/dashboard")

    # Count votes for this election
    total_votes = Vote.query.filter_by(
        election_id=election.id
    ).count()

    # ❌ RULE 2: Election started AND votes exist → block
    if start and now >= start and total_votes > 0:
        flash(
            "Cannot delete candidate — the election has started and votes have been cast."
        )
        return redirect(request.referrer or "/admin/dashboard")

    # ✅ RULE 3: Allowed (not started OR started with zero votes)
    db.session.delete(candidate)
    db.session.commit()

    if start and now >= start:
        flash("Candidate deleted successfully (no votes were cast).")
    else:
        flash("Candidate deleted successfully before the election started.")

    return redirect(request.referrer or "/admin/dashboard")




@app.route("/admin/candidate/update", methods=["POST"])
def update_candidate():

    c = Candidate.query.get(request.form["candidate_id"])

    if not c:
        flash("Candidate not found")
        return redirect("/admin/dashboard")

    election = Election.query.get(c.election_id)

    if election_has_ended(election):
        flash("Cannot edit candidate — election already ended")
        return redirect("/admin/dashboard")

    # name intentionally NOT editable
    c.party = request.form.get("party") or None
    c.description = request.form.get("description") or None

    uploaded = request.files.get("photo")
    if uploaded and uploaded.filename:
        filename = save_uploaded_file(uploaded)
        c.photo = filename

    db.session.commit()

    flash("Candidate updated")
    return redirect(request.referrer or "/admin/dashboard")


# -------------------------------------------------
# WHITELIST (PRIVATE ONLY)
# -------------------------------------------------
from flask import request

@app.route("/admin/whitelist/add", methods=["POST"])
def whitelist_add():

    election = Election.query.get(request.form.get("election_id"))
    if not election:
        flash("Election not found")
        return redirect(request.referrer or "/admin/dashboard")

    email = (request.form.get("email") or "").strip().lower()

    # ❌ basic email validation
    if not email or "@" not in email or "." not in email:
        flash("Enter a valid email address to add to whitelist")
        return redirect(request.referrer or "/admin/dashboard")

    # 🚫 BLOCK if election already ended
    if election_has_ended(election):
        flash("Cannot modify whitelist — election already ended")
        return redirect(request.referrer or "/admin/dashboard")

    # 🚫 PRIVATE ONLY
    if election.election_type != "private":
        flash("Whitelist only for private elections")
        return redirect(request.referrer or "/admin/dashboard")

    # 🚫 DUPLICATE CHECK
    if VoterWhitelist.query.filter_by(
        election_id=election.id,
        email=email
    ).first():
        flash("Email already added")
        return redirect(request.referrer or "/admin/dashboard")

    # ✅ ADD
    db.session.add(
        VoterWhitelist(
            election_id=election.id,
            email=email
        )
    )
    db.session.commit()

    flash("Email added to whitelist")
    return redirect(request.referrer or "/admin/dashboard")


@app.route("/admin/whitelist/bulk-add", methods=["POST"])
def whitelist_bulk_add():

    election = Election.query.get(request.form.get("election_id"))

    if not election:
        flash("Election not found")
        return redirect(request.referrer or "/admin/dashboard")

    # 🚫 BLOCK if election already ended
    if election_has_ended(election):
        flash("Cannot modify whitelist — election already ended")
        return redirect(request.referrer or "/admin/dashboard")

    # 🚫 PRIVATE ONLY
    if election.election_type != "private":
        flash("Whitelist allowed only for private elections")
        return redirect(request.referrer or "/admin/dashboard")

    raw_emails = request.form.get("emails", "")

    emails = [
        e.strip().lower()
        for e in raw_emails.replace(",", "\n").split("\n")
        if e.strip()
    ]

    added = 0
    skipped_invalid = 0
    skipped_duplicate = 0

    for email in emails:

        # ❌ invalid email
        if "@" not in email or "." not in email:
            skipped_invalid += 1
            continue

        # ❌ duplicate
        if VoterWhitelist.query.filter_by(
            election_id=election.id,
            email=email
        ).first():
            skipped_duplicate += 1
            continue

        db.session.add(
            VoterWhitelist(
                election_id=election.id,
                email=email
            )
        )
        added += 1

    db.session.commit()

    # 📢 precise feedback
    if added:
        flash(f"{added} email(s) added to whitelist")
    if skipped_invalid:
        flash(f"{skipped_invalid} invalid email(s) skipped")
    if skipped_duplicate:
        flash(f"{skipped_duplicate} duplicate email(s) skipped")

    return redirect(request.referrer or "/admin/dashboard")

@app.route("/admin/whitelist/remove/<wid>")
def whitelist_remove(wid):

    entry = VoterWhitelist.query.get(wid)

    if not entry:
        flash("Record not found")
        return redirect("/admin/dashboard")

    election = Election.query.get(entry.election_id)
    has_voted = Vote.query.filter_by(
        election_id=election.id,
        email=entry.email
    ).first()

    if has_voted:
        flash("Cannot remove voter — this voter has already voted")
        return redirect("/admin/dashboard")

    # 🚫 BLOCK if election already ended
    if election_has_ended(election):
        flash("Cannot modify whitelist — election already ended")
        return redirect("/admin/dashboard")

    db.session.delete(entry)
    db.session.commit()

    flash("Email removed from whitelist")
    return redirect(request.referrer or "/admin/dashboard")



# -------------------------------------------------
# TOGGLE RESULT VISIBILITY
# -------------------------------------------------

@app.route("/admin/toggle-results/<id>")
def toggle_results(id):

    e = Election.query.get(id)
    e.result_visible = not e.result_visible
    db.session.commit()

    flash("Result visibility updated")
    return redirect("/admin/dashboard")


# -------------------------------------------------
# DELETE ELECTION (safe)
# -------------------------------------------------

@app.route("/admin/election/delete/<eid>")
def delete_election(eid):

    election = Election.query.get(eid)
    if not election:
        flash("Election not found")
        return redirect("/admin/dashboard")

    now = datetime.now()
    start = datetime.fromisoformat(election.start_time) if election.start_time else None

    # ❌ STARTED → block normal delete
    if start and now >= start:
        flash("Election already started — use force delete")
        return redirect("/admin/dashboard")

    # ❌ votes safety
    if Vote.query.filter_by(election_id=eid).count() > 0:
        flash("Election has votes — cannot delete directly")
        return redirect("/admin/dashboard")

    db.session.delete(election)
    db.session.commit()

    flash("Election deleted successfully")
    return redirect("/admin/dashboard")



# -------------------------------------------------
# FORCE DELETE (danger — removes votes)
# -------------------------------------------------

@app.route("/admin/election/force-delete/<eid>")
def force_delete_election(eid):

    election = Election.query.get(eid)
    if not election:
        flash("Election not found")
        return redirect("/admin/dashboard")

    now = datetime.now()
    start = datetime.fromisoformat(election.start_time) if election.start_time else None

    # ❌ NOT STARTED → block force delete
    if not start or now < start:
        flash("Force delete allowed only after election has started")
        return redirect("/admin/dashboard")

    db.session.delete(election)
    db.session.commit()

    flash("Election and all related data deleted permanently")
    return redirect("/admin/dashboard")

@app.route("/admin/election/edit-time", methods=["POST"])
def edit_election_time():

    election = Election.query.get(request.form["election_id"])

    if election_has_ended(election):
        flash("Cannot change time — election already ended")
        return redirect("/admin/dashboard")

    election.start_time = request.form.get("start_time") or None
    election.end_time = request.form.get("end_time") or None

    db.session.commit()

    flash("Election time updated")
    return redirect(request.referrer or "/admin/dashboard")
from datetime import datetime, timezone
@app.route("/admin/election/update", methods=["POST"])
def update_election():

    e = Election.query.get(request.form["election_id"])
    if not e:
        flash("Election not found")
        return redirect(url_for(
            "admin_dashboard",
            open="edit",
            eid=e.id,
            name=e.name,
            start=e.start_time or "",
            end=e.end_time or ""
        ))

    now = datetime.now()

    start_old = datetime.fromisoformat(e.start_time) if e.start_time else None
    end_old   = datetime.fromisoformat(e.end_time) if e.end_time else None

    # 🚫 ENDED → nothing editable
    if end_old and now >= end_old:
        flash("Cannot edit — election already ended")
        return redirect(url_for(
            "admin_dashboard",
            open="edit",
            eid=e.id,
            name=e.name,
            start=e.start_time or "",
            end=e.end_time or ""
        ))

    name = request.form["name"].strip()
    start_raw = request.form.get("start_time") or None
    end_raw   = request.form.get("end_time") or None

    try:
        start_new = datetime.fromisoformat(start_raw) if start_raw else None
        end_new   = datetime.fromisoformat(end_raw) if end_raw else None
    except ValueError:
        flash("Invalid date/time format")
        return redirect(url_for(
            "admin_dashboard",
            open="edit",
            eid=e.id,
            name=e.name,
            start=e.start_time or "",
            end=e.end_time or ""
        ))

    # ❌ Start time in past
    if start_new and start_new < now:
        flash("Start time cannot be in the past")
        return redirect(url_for(
            "admin_dashboard",
            open="edit",
            eid=e.id,
            name=e.name,
            start=e.start_time or "",
            end=e.end_time or ""
        ))

    # 🟡 STARTED → start time locked
    if start_old and now >= start_old:
        if start_new and start_new != start_old:
            flash("Start time cannot be edited after election has started")
            return redirect(url_for(
                "admin_dashboard",
                open="edit",
                eid=e.id,
                name=e.name,
                start=e.start_time or "",
                end=e.end_time or ""
            ))
        start_new = start_old

    # ❌ start >= end
    if start_new and end_new and start_new >= end_new:
        flash("Start time must be before end time")
        return redirect(url_for(
            "admin_dashboard",
            open="edit",
            eid=e.id,
            name=e.name,
            start=e.start_time or "",
            end=e.end_time or ""
        ))

    # ❌ end in past
    if end_new and end_new <= now:
        flash("End time must be after the current time")
        return redirect(url_for(
            "admin_dashboard",
            open="edit",
            eid=e.id,
            name=e.name,
            start=e.start_time or "",
            end=e.end_time or ""
        ))

    # ❌ private needs both times
    if e.election_type == "private" and (not start_new or not end_new):
        flash("Private elections must have valid start and end time")
        return redirect(url_for(
            "admin_dashboard",
            open="edit",
            eid=e.id,
            name=e.name,
            start=e.start_time or "",
            end=e.end_time or ""
        ))

    # ✅ SAVE
    e.name = name
    e.start_time = start_new.isoformat() if start_new else None
    e.end_time   = end_new.isoformat() if end_new else None

    db.session.commit()

    flash("Election updated successfully")
    return redirect(url_for(
        "admin_dashboard",
        open="edit",
        eid=e.id,
        name=e.name,
        start=e.start_time or "",
        end=e.end_time or ""
    ))



# -------------------------------------------------
# LOGOUT
# -------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "admin_login_success")

    return redirect("/")

# -------------------------------------------------
if __name__ == "__main__":
    # Get port from environment or default to 5000
    port = int(os.environ.get("PORT", 5000))
    
    # Check if we are running on Render (Render sets the 'RENDER' env var to 'true')
    # If not on Render, debug will be True for your local VS Code
    is_on_render = os.environ.get("RENDER") == "true"
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=not is_on_render
    )