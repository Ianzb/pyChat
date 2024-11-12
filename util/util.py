import secrets
import string


def gen_str(length):
    letters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(letters) for _ in range(length))
