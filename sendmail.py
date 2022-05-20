import hashlib
import pyotp
import smtplib
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")


def send_mail(mail, email):
    secret = hashlib.md5(email.encode()).hexdigest()
    secret = secret.replace('1', 'x').replace('0', 'w').replace('9', 'z').replace('8', 'y')
    totp = pyotp.TOTP(str(secret), interval=300)
    OTP = totp.now()
    # print(OTP)
    if mail:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, PASSWORD)
        msg_cnt = f"""
        <h3> OTP to Change on MR Raja Jewellers {email} </h3>
        <h1> {OTP} </h1>"""
        message = MIMEText(msg_cnt, 'html')
        message['From'] = "MR Raja Jewellers"

        message['Subject'] = "OTP For Change of Password"
        msg = message.as_string()
        try:
            server.sendmail(EMAIL_ADDRESS, email, msg)
        except Exception as e:
            print(e)
        server.quit()

    return OTP
