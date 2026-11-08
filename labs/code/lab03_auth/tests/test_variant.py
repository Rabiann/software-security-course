"""Мінімальний набір тестів за вимогами Кроку 7 Лабораторної роботи 3."""
import pytest
from auth.passwords import hash_password, verify_password
from auth.lockout import record_attempt, is_allowed, STORAGE, WINDOW_SIZE, WINDOW_INTEREVAL_MS
from auth import codes


# 1. Зворотність hash_password / verify_password (правильний пароль)
def test_password_verify_correct():
    pwd = "MySecretPassword123"
    stored = hash_password(pwd)
    assert verify_password(stored, pwd) is True


# 2. Відмова для хибного пароля
def test_password_verify_wrong():
    pwd = "MySecretPassword123"
    stored = hash_password(pwd)
    assert verify_password(stored, "WrongPassword") is False


# 3. Унікальність солі (однаковий пароль -> різні хеші)
def test_salt_uniqueness():
    pwd = "SamePassword"
    assert hash_password(pwd) != hash_password(pwd)


# 4. Спрацювання блокування після ліміту спроб
def test_lockout_limit():
    account = "test_user"
    STORAGE[account] = []
    now = 1000

    # 4 спроби — ще дозволено
    for i in range(4):
        record_attempt(account, ok=False, now=now + i * 100)
    assert is_allowed(account, now + 400) is True

    # 5-а спроба (досягнуто WINDOW_SIZE = 5) — блокування
    record_attempt(account, ok=False, now=now + 400)
    assert is_allowed(account, now + 400) is False

    # Спливання вікна (now + WINDOW_INTEREVAL_MS + 1) — розблокування
    assert is_allowed(account, now + WINDOW_INTEREVAL_MS + 1) is True


# 5. Другий фактор: перевірка одноразового коду та захист від повторного використання
def test_recovery_codes():
    test_code = list(codes.CODES)[0]
    
    # Перше пред'явлення — успіх (True)
    assert codes.validate(test_code) is True
    
    # Повторне пред'явлення того самого коду — відхилення (False)
    assert codes.validate(test_code) is False
    
    # Невірний код — відхилення (False)
    assert codes.validate("INVALID-CODE-999") is False
