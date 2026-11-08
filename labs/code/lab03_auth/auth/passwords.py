"""Зберігання та перевірка паролів — КАРКАС для лабораторної роботи 3.

Здобувач реалізує функцію зберігання за KDF свого варіанта
(Argon2id / scrypt / bcrypt / PBKDF2), додає «перець» і перевірку за сталий час.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import bcrypt

PEPPER = os.environ.get("AUTH_PEPPER", "").encode()
rounds = 12

# ВРАЗЛИВИЙ зразок (для порівняння у звіті) — НЕ використовувати:
def hash_password_insecure(password: str) -> str:
    # ВРАЗЛИВО: швидка хеш-функція без солі — вразлива до райдужних таблиць.
    return hashlib.sha256(password.encode()).hexdigest()

def _peppered(data: bytes) -> bytes:
    return hmac.new(PEPPER, data, hashlib.sha256).digest() if PEPPER else data

def hash_password(password: str) -> str:
    """БЕЗПЕЧНО: реалізуйте зберігання за KDF свого варіанта.

    Вимоги:
      – унікальна випадкова сіль на кожен пароль (>= 16 байтів);
      – «перець» із секретного сховища (тут — змінна середовища PEPPER);
      – параметри KDF за чинними рекомендаціями (RFC 9106 для Argon2id).
    """
    # TODO(варіант): повернути рядок формату, що містить параметри, сіль і хеш.
    salt = bcrypt.gensalt(rounds=rounds)
    salt_str = salt.split(b"$")[3].decode('ascii')
    data = _peppered(password.encode())
    hashed = bcrypt.hashpw(data, salt)
    dk = hashed[len(salt):].decode('ascii')
    return f'bcrypt$rounds={rounds}${salt_str}${dk}'


def verify_password(stored: str, password: str) -> bool:
    """Перевірка пароля. Порівняння тегів — лише за сталий час (hmac.compare_digest)."""
    if stored.startswith('bcrypt'):
        _, stored_rounds, salt_str, stored_dk = stored.split('$')
        rounds_val = stored_rounds.split('=')[1]
        salt = b'$2b$' + rounds_val.encode('ascii') + b'$' + salt_str.encode('ascii')
        data = _peppered(password.encode())
        hashed = bcrypt.hashpw(data, salt)
        dk = hashed[len(salt):].decode('ascii')
        return hmac.compare_digest(dk, stored_dk)

    return False


def benchmark_hashing(password: str = "TestPassword#2026", bcrypt_runs: int = 5, sha_runs: int = 1000) -> dict[str, float]:
    """Вимірює та порівнює швидкість обчислення bcrypt проти SHA-256 (Крок 4)."""
    # 1. Замір швидкої вразливої функції SHA-256 (середнє з 1000 запусків)
    t0 = time.perf_counter()
    for _ in range(sha_runs):
        hash_password_insecure(password)
    t_sha = (time.perf_counter() - t0) / sha_runs

    # 2. Замір повільної захищеної функції bcrypt (середнє з кількох запусків)
    t0 = time.perf_counter()
    for _ in range(bcrypt_runs):
        hash_password(password)
    t_bcrypt = (time.perf_counter() - t0) / bcrypt_runs

    ratio = t_bcrypt / t_sha

    print("=== Порівняльний бенчмарк продуктивності (Крок 4) ===")
    print(f"Вразливий SHA-256 (без солі):  {t_sha * 1e6:.2f} µs ({t_sha * 1e3:.5f} ms)")
    print(f"Захищений bcrypt (cost={rounds}):     {t_bcrypt * 1e3:.2f} ms")
    print(f"-> bcrypt повільніший у ~{ratio:,.0f} разів!")
    print("=====================================================")

    return {
        "sha_ms": t_sha * 1e3,
        "bcrypt_ms": t_bcrypt * 1e3,
        "ratio": ratio
    }


if __name__ == "__main__":
    pwd = "12345678"
    h = hash_password(pwd)
    print("Verify correct:", verify_password(h, pwd))
    print("Verify wrong:", verify_password(h, "wrong"))
    print()
    benchmark_hashing(pwd)
