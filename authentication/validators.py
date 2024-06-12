from django.core.exceptions import ValidationError

def validate_password(value, min_length=8, min_lowercase=1, min_uppercase=1, min_digits=1, min_special_characters=1):
    if len(value) < min_length:
        raise ValidationError("The password must be at least {} characters long.".format(min_length))
    if sum(1 for char in value if char.isupper()) < min_uppercase:
        raise ValidationError("The password must contain at least {} uppercase letter(s).".format(min_uppercase))
    if sum(1 for char in value if char.islower()) < min_lowercase:
        raise ValidationError("The password must contain at least {} lowercase letter(s).".format(min_lowercase))
    if sum(1 for char in value if char.isdigit()) < min_digits:
        raise ValidationError("The password must contain at least {} digit(s).".format(min_digits))
    special_chars = "!@#$%^&*()-_=+[]{};:'\",.<>?/"
    if sum(1 for char in value if char in special_chars) < min_special_characters:
        raise ValidationError("The password must contain at least {} special character(s) (!@#$%^&*()-_=+[]{{}};:'\",.<>?/).".format(min_special_characters))
