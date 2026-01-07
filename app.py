import os
import random
import smtplib
import string
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    session, flash
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
# SMTP — GMAIL OTP SETUP
# -------------------------------------------------

import os

SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")

def send_otp_email(to, subject, text):
    print("SMTP DEBUG — email:", SMTP_EMAIL, "password:", bool(SMTP_PASSWORD))

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("⚠️ SMTP NOT CONFIGURED — OTP NOT SENT")
        return

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            message = f"Subject: {subject}\n\n{text}"
            smtp.sendmail(SMTP_EMAIL, to, message)

        print("✅ OTP EMAIL SENT TO:", to)

    except Exception as e:
        print("❌ SMTP ERROR:", e)




def generate_otp():
    return str(random.randint(100000, 999999))


def generate_admin_code():
    return ''.join(random.choices(string.digits, k=6))


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
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=5)
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

# -------------------------------------------------
# DATABASE MODELS
# -------------------------------------------------

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120))
    username = db.Column(db.String(80), unique=True)
    mobile = db.Column(db.String(20))
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
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


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


# -------------------------------------------------
# HOME / LOGIN PAGE
# -------------------------------------------------

@app.route("/")
def index():
    session.pop("otp_reset_verified", None)
    session.pop("reset_email", None)
    return render_template("login.html")

# -------------------------------------------------
# ADMIN LOGIN
# -------------------------------------------------

@app.route("/admin/login", methods=["POST"])
def admin_login():

    username = request.form["username"]
    password = request.form["password"]

    admin = Admin.query.filter_by(username=username).first()

    if not admin or not check_password_hash(admin.password, password):
        flash("Invalid username or password", "admin_login_error")

        return redirect("/")

    session["admin_id"] = admin.id
    return redirect("/admin/dashboard")


# -------------------------------------------------
# ADMIN REGISTRATION (OTP FLOW)
# -------------------------------------------------

@app.route("/admin/register", methods=["POST"])
def admin_register():

    name     = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    mobile   = request.form.get("mobile", "").strip()
    email    = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm", "")

    # ---- preserve entered values ----
    session["register_form"] = request.form

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

    send_otp_email(
        email,
        "Admin Registration OTP",
        f"Your OTP is {otp}"
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
        flash("Invalid OTP", "otp_error")
        return redirect("/verify-otp")

    # ---- expired ----
    if record.expires_at < datetime.utcnow():
        flash("OTP expired — request a new one", "otp_error")
        return redirect("/voter/otp")


    # ---- delete OTP ----
    db.session.delete(record)
    db.session.commit()

    # ---- create admin ----
    new_admin = Admin(
        name=pending["name"],
        username=pending["username"],
        mobile=pending["mobile"],
        email=pending["email"],
        password=pending["password"],
        admin_code=generate_admin_code()
    )

    db.session.add(new_admin)
    db.session.commit()

    send_otp_email(
        new_admin.email,
        "Admin Account Created",
        f"Username: {new_admin.username}\nAdmin Code: {new_admin.admin_code}"
    )

    # cleanup
    session.pop("pending_admin", None)
    session.pop("otp_context", None)

    flash("Registration successful — you may login now", "otp_success")
    return redirect("/?panel=login")

# -------------------------------------------------
# ADMIN FORGOT PASSWORD — REQUEST RESET OTP
# -------------------------------------------------

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

        send_otp_email(
            email,
            "Admin Password Reset OTP",
            f"Your OTP to reset password is: {otp}"
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
        flash("Invalid OTP", "otp_error")
        return redirect("/verify-otp?context=reset")

    if record.expires_at < datetime.utcnow():
        flash("OTP expired — request new reset link", "otp_error")
        return redirect("/")

    # delete otp after verification
    db.session.delete(record)
    db.session.commit()

    session["otp_reset_verified"] = True

    flash("OTP verified — create your new password", "otp_success")
    return redirect("/verify-otp?context=reset")
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

    password = request.form["password"]
    confirm  = request.form["confirm"]

    if password != confirm:
        flash("Passwords do not match", "otp_error")
        return redirect("/verify-otp?context=reset")

    admin.password = generate_password_hash(password)
    db.session.commit()

    # cleanup session
    session.pop("otp_reset_verified", None)
    session.pop("reset_email", None)
    session.pop("otp_context", None)

    flash("Password updated successfully — login again", "otp_success")
    return redirect("/?panel=login")

@app.route("/admin/reset-resend")
def admin_reset_resend():

    email = session.get("reset_email")
    if not email:
        flash("Session expired — restart reset process", "otp_error")
        return redirect("/")

    otp = generate_otp()
    store_new_otp(email, otp, "admin_reset")

    send_otp_email(email, "Admin Password Reset OTP", f"Your OTP is {otp}")

    flash("New OTP sent to your email", "otp_success")
    return redirect("/verify-otp?context=reset")
@app.route("/voter/resend-otp")
def voter_resend_otp():

    email = session.get("voter_email")
    if not email:
        flash("Session expired — start login again", "otp_error")
        return redirect("/")

    role = "voter_private" if "voter_admin_id" in session else "voter_public"

    otp = generate_otp()
    store_new_otp(email, otp, role)

    send_otp_email(email, "Voting Login OTP", f"Your new OTP is {otp}")

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

    send_otp_email(email, "Admin Registration OTP", f"Your OTP is {otp}")

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

    send_otp_email(email, "Voting Login OTP", f"Your OTP is {otp}")

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

    send_otp_email(email, "Private Voting OTP", f"Your OTP is {otp}")

    session["voter_email"] = email
    session["voter_admin_id"] = admin.id

    flash("OTP sent to your email", "voter_private_success")
    return redirect("/voter/otp")



# -------------------------------------------------
# VERIFY VOTER OTP
# -------------------------------------------------

@app.route("/voter/otp", methods=["GET", "POST"])
def voter_verify():

    # prevent admin reset state leaking into voter login
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
        flash("Invalid OTP", "otp_error")

        return redirect("/voter/otp")

    if record.expires_at < datetime.utcnow():
        flash("OTP expired — request a new OTP", "otp_error")
        return redirect("/")
    # OTP verified — delete it permanently
    db.session.delete(record)
    db.session.commit()

    if not record:
        flash("Invalid OTP", "otp_error")

        return redirect("/voter/otp")

    session["voter_logged"] = True
    return redirect("/voter/dashboard")


# -------------------------------------------------
# VOTER DASHBOARD
# -------------------------------------------------

@app.route("/voter/dashboard")
def voter_dashboard():

    if not require_voter_login():
        return redirect("/")
    # prevent admin account from entering voter area
    if "admin_id" in session:
        flash("Admins cannot access voter panel")
        return redirect("/admin/dashboard")


    email = session["voter_email"]
    q = request.args.get("q", "").strip().lower()

    voted_set = {v.election_id for v in Vote.query.filter_by(email=email).all()}

    # ---- PUBLIC LOGIN VOTER ----
    if "voter_admin_id" not in session:

        # show only PUBLIC elections (all admins)
        elections = Election.query.filter_by(election_type="public").all()

    # ---- PRIVATE LOGIN VOTER ----
    else:
        admin_id = session["voter_admin_id"]

        # show ONLY elections created by that admin
        # (both public + private)
        elections = Election.query.filter_by(admin_id=admin_id).all()



    voted_set = {v.election_id for v in Vote.query.filter_by(email=email).all()}

    election_list = []

    for e in elections:

        # SEARCH FILTERING
        if q:

            text = (e.name or "").lower()
            code = (e.public_code or "").lower()

            # 🟢 PUBLIC LOGIN — search public elections only
            if "voter_admin_id" not in session:
                if q not in text and q not in code:
                    continue

            # 🟢 PRIVATE LOGIN — search public + own private
            else:
                if q not in text and q not in code:
                    continue


        total_votes = Vote.query.filter_by(election_id=e.id).count()

        candidate_count = Candidate.query.filter_by(election_id=e.id).count()

        allowed = True

        # CHECK whitelist only for private elections
        if e.election_type == "private":
            allowed = VoterWhitelist.query.filter_by(
                election_id=e.id,
                email=email.lower()
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
            "allowed": allowed
            
        })



    return render_template(
        "voter_dashboard.html",
        elections=election_list,
        email=email,
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
            "can_view": can_view
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

    result = []
    max_votes = 0

    for c in candidates:
        count = Vote.query.filter_by(candidate_id=c.id).count()
        max_votes = max(max_votes, count)

        result.append({
            "name": c.name,
            "count": count
        })

    # tie-safe winner detection
    for r in result:
            r["winner"] = (r["count"] == max_votes and max_votes > 0)

    total_votes = Vote.query.filter_by(election_id=election.id).count()

    return render_template(
        "voter_result_detail.html",
        election=election,
        result=result,
        total_votes=total_votes
    )

@app.route("/election/<eid>")
def view_election(eid):

    if not require_voter_login():
        return redirect("/")

    email = session["voter_email"]
    election = Election.query.get_or_404(eid)
    # 🚫 Block viewing private elections of other admins
    if election.election_type == "private" and "voter_admin_id" in session:
        if election.admin_id != session["voter_admin_id"]:
            flash("You are not allowed to access this election")
            return redirect("/voter/dashboard")


    # count total votes
    total_votes = Vote.query.filter_by(election_id=eid).count()

    # PRIVATE — enforce whitelist BEFORE showing candidates
    if election.election_type == "private":

        allowed = VoterWhitelist.query.filter_by(
            election_id=eid,
            email=email
        ).first()

        if not allowed:
            flash("You are not allowed to view this election")
            return redirect("/voter/dashboard")

        candidates = Candidate.query.filter_by(election_id=eid).all()

    else:
        # PUBLIC — everyone may view candidates
        candidates = Candidate.query.filter_by(election_id=eid).all()

    # voting status
    voted = Vote.query.filter_by(
        election_id=eid,
        email=email
    ).first()

    return render_template(
        "single_election.html",
        election=election,
        candidates=candidates,
        total_votes=total_votes,
        email=email,
        voted=voted,
        vote_time=voted.timestamp if voted else None
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

    election = Election.query.get(election_id)

    if Candidate.query.filter_by(election_id=election_id).count() < 2:
        flash("Minimum 2 candidates required")
        return redirect("/voter/dashboard")

    if election.election_type == "private":
        allowed = VoterWhitelist.query.filter_by(
            election_id=election_id,
            email=email
        ).first()
        if not allowed:
            flash("Email not allowed for this election", "voter_error")
            return redirect("/voter/dashboard")

    if election.start_time and datetime.now() < datetime.fromisoformat(election.start_time):
        flash("Election has not started yet")
        return redirect("/voter/dashboard")

    if election.end_time and datetime.now() > datetime.fromisoformat(election.end_time):
        flash("Election ended")
        return redirect("/voter/dashboard")

    existing_vote = Vote.query.filter_by(
        election_id=election_id,
        email=email
    ).first()

    if existing_vote:
        if datetime.utcnow() - existing_vote.timestamp <= timedelta(seconds=10):
            existing_vote.candidate_id = candidate_id
            existing_vote.timestamp = datetime.utcnow()
            db.session.commit()
            flash("Vote updated")
            return redirect("/voter/dashboard")

        flash("You already voted")
        return redirect("/voter/dashboard")

    db.session.add(Vote(
        election_id=election_id,
        candidate_id=candidate_id,
        email=email
    ))

    db.session.commit()
    flash("Vote cast successfully")
    return redirect("/voter/dashboard")


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

    admin = Admin.query.get(session.get("admin_id"))
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

    for e in elections:

        total_votes = Vote.query.filter_by(election_id=e.id).count()
        candidate_count = Candidate.query.filter_by(election_id=e.id).count()

        # determine whether results should display
        now = datetime.now()
        ended = False
        if e.end_time:
            ended = now >= datetime.fromisoformat(e.end_time)

        # Winner visibility rule
        show_winner = ended   # <-- IMPORTANT

        result_list.append({
            "id": e.id,
            "name": e.name,
            "type": e.election_type,
            "candidate_count": candidate_count,
            "total_votes": total_votes,
            "ended": ended,
            "visible": e.result_visible,
            "show_winner": show_winner
        })


    return render_template(
        "admin_results.html",
        elections=result_list,
        admin=admin
    )
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
        flash("Private election results unlock only after end time")
        return redirect("/admin/results")

    candidates = Candidate.query.filter_by(election_id=election.id).all()

    result = []
    max_votes = 0

    for c in candidates:
        count = Vote.query.filter_by(candidate_id=c.id).count()
        max_votes = max(max_votes, count)

        result.append({
            "id": c.id,
            "name": c.name,
            "photo": c.photo,
            "party": c.party,
            "description": c.description,
            "count": count
        })

    # mark winners — only meaningful when election ended
    for r in result:
        r["winner"] = (ended and r["count"] == max_votes and max_votes > 0)

    total_votes = Vote.query.filter_by(election_id=election.id).count()

    return render_template(
        "admin_result_detail.html",
        election=election,
        result=result,
        total_votes=total_votes,
        ended=ended        # <-- winner logic flag
    )


# -------------------------------------------------
# CREATE ELECTION
# -------------------------------------------------

@app.route("/admin/create-election", methods=["POST"])
def create_election():

    etype = request.form["type"]

    start = request.form.get("start_time") or None
    end   = request.form.get("end_time") or None

    # private requires time
    if etype == "private" and (not start or not end):
        flash("Private elections must have a start and end time")
        return redirect("/admin/dashboard")

    election = Election(
        admin_id=session["admin_id"],
        name=request.form["name"],
        election_type=etype,
        start_time=start,
        end_time=end
    )

    if etype == "public":
        election.public_code = generate_public_code()

    db.session.add(election)
    db.session.commit()

    flash("Election created — add minimum 2 candidates")
    return redirect("/admin/dashboard")



# -------------------------------------------------
# ADD CANDIDATE
# -------------------------------------------------

@app.route("/admin/add-candidate", methods=["POST"])
def add_candidate():

    election = Election.query.get(request.form["election_id"])

    if election_has_ended(election):
        flash("Cannot add candidate — election already ended")
        return redirect("/admin/dashboard")

    photo_filename = save_uploaded_file(request.files.get("photo"))

    candidate = Candidate(
        election_id=election.id,
        name=request.form["name"].strip(),
        party=request.form.get("party") or None,
        description=request.form.get("description") or None,
        photo=photo_filename
    )

    db.session.add(candidate)
    db.session.commit()

    flash("Candidate added")
    return redirect("/admin/dashboard")



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
    return redirect("/admin/dashboard")



# -------------------------------------------------
# DELETE CANDIDATE (only if no votes)
# -------------------------------------------------

@app.route("/admin/candidate/delete/<cid>")
def delete_candidate(cid):

    candidate = Candidate.query.get(cid)

    if not candidate:
        flash("Candidate not found")
        return redirect("/admin/dashboard")

    election = Election.query.get(candidate.election_id)

    if election_has_ended(election):
        flash("Cannot delete candidate — election already ended")
        return redirect("/admin/dashboard")

    if Vote.query.filter_by(candidate_id=cid).count() > 0:
        flash("Cannot delete — votes exist")
        return redirect("/admin/dashboard")

    db.session.delete(candidate)
    db.session.commit()

    flash("Candidate deleted")
    return redirect("/admin/dashboard")

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
    return redirect("/admin/dashboard")


# -------------------------------------------------
# WHITELIST (PRIVATE ONLY)
# -------------------------------------------------

@app.route("/admin/whitelist/add", methods=["POST"])
def whitelist_add():

    election = Election.query.get(request.form["election_id"])
    email = request.form["email"].strip().lower()

    # 🚫 BLOCK if election already ended
    if election_has_ended(election):
        flash("Cannot modify whitelist — election already ended")
        return redirect("/admin/dashboard")

    if election.election_type != "private":
        flash("Whitelist only for private elections")
        return redirect("/admin/dashboard")

    if VoterWhitelist.query.filter_by(election_id=election.id, email=email).first():
        flash("Email already added")
        return redirect("/admin/dashboard")

    db.session.add(VoterWhitelist(election_id=election.id, email=email))
    db.session.commit()

    flash("Email added to whitelist")
    return redirect("/admin/dashboard")



@app.route("/admin/whitelist/remove/<wid>")
def whitelist_remove(wid):

    entry = VoterWhitelist.query.get(wid)

    if not entry:
        flash("Record not found")
        return redirect("/admin/dashboard")

    election = Election.query.get(entry.election_id)

    # 🚫 BLOCK if election already ended
    if election_has_ended(election):
        flash("Cannot modify whitelist — election already ended")
        return redirect("/admin/dashboard")

    db.session.delete(entry)
    db.session.commit()

    flash("Email removed from whitelist")
    return redirect("/admin/dashboard")



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

    if election_has_ended(election):
        flash("Cannot delete — election already ended")
        return redirect("/admin/dashboard")

    if Vote.query.filter_by(election_id=eid).count() > 0:
        flash("Election has votes — cannot delete directly")
        return redirect("/admin/dashboard")

    db.session.delete(election)
    db.session.commit()

    flash("Election deleted")
    return redirect("/admin/dashboard")



# -------------------------------------------------
# FORCE DELETE (danger — removes votes)
# -------------------------------------------------

@app.route("/admin/election/force-delete/<eid>")
def force_delete_election(eid):

    election = Election.query.get(eid)

    db.session.delete(election)
    db.session.commit()

    flash("Election + votes deleted permanently")
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
    return redirect("/admin/dashboard")

@app.route("/admin/election/update", methods=["POST"])
def update_election():

    e = Election.query.get(request.form["election_id"])

    if election_has_ended(e):
        flash("Cannot edit — election already ended")
        return redirect("/admin/dashboard")

    e.name = request.form["name"].strip()

    e.start_time = request.form.get("start_time") or None
    e.end_time   = request.form.get("end_time") or None

    if e.election_type == "private" and (not e.start_time or not e.end_time):
        flash("Private elections must have a time period")
        return redirect("/admin/dashboard")

    db.session.commit()

    flash("Election updated")
    return redirect("/admin/dashboard")

@app.route("/admin/whitelist/bulk-add", methods=["POST"])
def whitelist_bulk_add():

    election = Election.query.get(request.form["election_id"])

    if election_has_ended(election):
        flash("Cannot modify whitelist — election already ended")
        return redirect("/admin/dashboard")

    if election.election_type != "private":
        flash("Whitelist allowed only for private elections")
        return redirect("/admin/dashboard")

    raw_emails = request.form["emails"]

    emails = [
        e.strip().lower()
        for e in raw_emails.replace(",", "\n").split("\n")
        if e.strip()
    ]

    added = 0

    for email in emails:
        if not VoterWhitelist.query.filter_by(
            election_id=election.id,
            email=email
        ).first():

            db.session.add(
                VoterWhitelist(election_id=election.id, email=email)
            )
            added += 1

    db.session.commit()

    flash(f"{added} emails added to whitelist")
    return redirect("/admin/dashboard")


# -------------------------------------------------
# LOGOUT
# -------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "admin_login_success")

    return redirect("/")

