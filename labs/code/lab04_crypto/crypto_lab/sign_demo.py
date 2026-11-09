from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
priv = rsa.generate_private_key(65537, 2048) # TODO(варіант): схема варіанта
pub = priv.public_key()
pss_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
msg = b"lab4 demo message"

sig = priv.sign(msg, pss_padding, hashes.SHA256())
print(sig[:32].hex())
pub.verify(sig, msg, pss_padding, hashes.SHA256()) # успіх — виняток не піднімається
print("OK: Correct verified")
msg += b'1'
try:
    pub.verify(sig, msg, pss_padding, hashes.SHA256())
    print("Error: Broken verified successfully")
except:
    print("OK: Broken verification failed")
