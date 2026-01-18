
SMTP_EMAIL = "control.your.voting@gmail.com"
SMTP_PASSWORD = "sydpdtgkauovfiee"


def send_otp_email(to, subject, text):
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            message = f"Subject: {subject}\n\n{text}"
            smtp.sendmail(SMTP_EMAIL, to, message)
    except Exception as e:
        print("SMTP ERROR:", e)




# 1. Get your API Key from https://www.promailer.xyz/
# 2. Add PROMAIL_API_KEY to Render Environment Variables
PROMAIL_API_KEY = os.environ.get("PROMAIL_API_KEY")
def send_otp_email(to, subject, html, text=None):
    if not PROMAIL_API_KEY:
        print("ERROR: PROMAIL_API_KEY missing")
        return False

    url = "https://mailserver.automationlounge.com/api/v1/messages/send"

    headers = {
        "Authorization": f"Bearer {PROMAIL_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "to": to,
        "subject": subject,
        "html": html
    }

    # optional plain text fallback
    if text:
        payload["text"] = text

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=10
        )

        print("ProMailer status:", response.status_code)
        print("ProMailer response:", response.text)

        if response.status_code == 200:
            return True
        return False

    except Exception as e:
        print("ProMailer Exception:", e)
        return False


# -------------------------------------------------
# SMTP — GMAIL OTP SETUP
# -------------------------------------------------
SMTP_EMAIL = "control.your.voting@gmail.com"
SMTP_PASSWORD = "sydpdtgkauovfiee"


def send_otp_email(to, subject, text):
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            message = f"Subject: {subject}\n\n{text}"
            smtp.sendmail(SMTP_EMAIL, to, message)
    except Exception as e:
        print("SMTP ERROR:", e)

def send_vote_central_email(to_email, subject, body):
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)

            message = f"""From: VoteCentral <{SMTP_EMAIL}>
To: {to_email}
Subject: {subject}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit

{body}
"""

            smtp.sendmail(
                SMTP_EMAIL,
                to_email,
                message.encode("utf-8")   # 🔒 THIS LINE FIXES THE CRASH
            )

            return True

    except Exception as e:
        print("EMAIL ERROR:", e)
        return False




# 1. Get your API Key from https://www.promailer.xyz/
# 2. Add PROMAIL_API_KEY to Render Environment Variables
PROMAIL_API_KEY = os.environ.get("PROMAIL_API_KEY")
def send_otp_email(to, subject, html, text=None):
    """
    Used ONLY for OTP-related emails (admin, voter, reset, resend)
    """
    if not PROMAIL_API_KEY:
        print("ERROR: PROMAIL_API_KEY missing")
        return False

    payload = {
        "to": to,
        "subject": subject,
        "html": html,
        "from": PROMAIL_SENDER
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

        if r.status_code == 200:
            return True

        print("ProMailer error:", r.status_code, r.text)
        return False

    except Exception as e:
        print("ProMailer exception:", e)
        return False

def send_vote_central_email(to_email, subject, body):
    """
    Used for ALL non-OTP system emails (admin code, confirmations, notices)
    """

    if not PROMAIL_API_KEY:
        print("ERROR: PROMAIL_API_KEY missing")
        return False

    # Convert plain text body → clean HTML
    html = body.replace("\n", "<br>")

    payload = {
        "to": to_email,
        "subject": subject,
        "html": f"""
        <div style="font-family:Arial,Helvetica,sans-serif;
                    font-size:14px;
                    line-height:1.6;
                    color:#111;">
            {html}
            <br><br>
            <hr style="border:none;border-top:1px solid #ddd">
            <small style="color:#666">
                VoteCentral · Secure · Verified · One Vote Per User
            </small>
        </div>
        """,
        "text": body,
        "from": PROMAIL_SENDER
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

        if r.status_code == 200:
            return True

        print("ProMailer error:", r.status_code, r.text)
        return False

    except Exception as e:
        print("ProMailer exception:", e)
        return False
