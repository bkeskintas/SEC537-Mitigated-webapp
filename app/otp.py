import pyotp

# A fixed OTP secret for demo (Store per user in production)
OTP_SECRET = "JBSWY3DPEHPK3PXP"

def generate_otp():
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.now()

def verify_otp(otp):
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.verify(otp)
