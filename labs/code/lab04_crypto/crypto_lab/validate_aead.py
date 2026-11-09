from aead import encrypt, decrypt

key = b'0' * 16
plaintext = b"Hello, world!"
associated = b'header'

blob = encrypt(plaintext, key, associated=associated)
message = decrypt(blob, key, associated)
print(message)

tampered = blob[:-1] + bytes([blob[-1] ^ 1])
try:
    decrypt(tampered, key, associated)
except:
    print("Error catched")