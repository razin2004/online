
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