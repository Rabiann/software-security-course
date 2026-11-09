from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
key = b'0' * 16
blockA = b'A' * 16
blockB = b'B' * 16
plaintext = blockA + blockA + blockB

# ВРАЗЛИВО
cipher_ecb = Cipher(algorithms.AES(key), modes.ECB())
encryptor = cipher_ecb.encryptor()
data_ecb = encryptor.update(plaintext) + encryptor.finalize()

f1 = data_ecb[:16]
f2 = data_ecb[16:32]
f3 = data_ecb[32:48]
assert f1 == f2
print(f1, f2)

# БЕЗПЕЧНО
aesgcm = AESGCM(key)
nonce = os.urandom(12)
data_aesgcm = aesgcm.encrypt(nonce, plaintext, b'')

f1 = data_aesgcm[:16]
f2 = data_aesgcm[16:32]
f3 = data_aesgcm[32:48]
assert f1 != f2
print(f1, f2)
