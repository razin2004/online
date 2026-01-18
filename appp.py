
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
