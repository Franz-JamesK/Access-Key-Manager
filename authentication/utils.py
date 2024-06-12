import random


# generate 6-digit OTP
def generate_otp():
    # Generate a 6-digit random integer
    otp = random.randint(100000, 999999)
    return otp
