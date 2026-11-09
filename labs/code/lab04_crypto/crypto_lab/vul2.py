import hashlib
import bcrypt

password1 = b"12345678"
password2 = b"12345678"

# ВРАЗЛИВО
h1 = hashlib.sha256(password1).hexdigest()
h2 = hashlib.sha256(password2).hexdigest()
assert h1 == h2
print(h1, h2)

# БЕЗПЕЧНО
salt1 = bcrypt.gensalt(12)
h1_sec = bcrypt.hashpw(password1, salt1)
salt2 = bcrypt.gensalt(12)
h2_sec = bcrypt.hashpw(password2, salt2)
assert h1_sec != h2_sec
print(h1_sec, h2_sec)