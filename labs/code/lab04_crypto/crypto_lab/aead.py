"""Симетричне шифрування — КАРКАС для лабораторної роботи 4.

Здобувач реалізує шифрування за AEAD свого варіанта і демонструє наслідки
двох типових помилок зі свого завдання (ECB, повторний nonce тощо).
"""
from __future__ import annotations
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(plaintext: bytes, key: bytes, associated: bytes = b"") -> bytes:
    """БЕЗПЕЧНО: реалізуйте автентифіковане шифрування (AES-GCM / ChaCha20-Poly1305).

    Вимоги:
      – унікальний nonce на кожне повідомлення (лекція 10);
      – прив'язка асоційованих даних;
      – повернення nonce разом із шифротекстом і тегом.
    """
    # TODO(варіант): використати cryptography.hazmat.primitives.ciphers.aead
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    return nonce + aesgcm.encrypt(nonce, plaintext, associated)


def decrypt(blob: bytes, key: bytes, associated: bytes = b"") -> bytes:
    # TODO(варіант): перевірити тег автентичності; за розбіжності — підняти виняток.
    aesgcm = AESGCM(key)
    nonce = blob[:12]
    data = blob[12:]
    return aesgcm.decrypt(nonce, data, associated)

