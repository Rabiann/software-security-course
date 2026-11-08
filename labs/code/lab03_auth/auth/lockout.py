WINDOW_SIZE = 5
WINDOW_INTEREVAL_MS = 300_000

STORAGE = {}

def record_attempt(account: str, ok: bool, now: float) -> None:
    if account not in STORAGE:
        STORAGE[account] = []
    
    STORAGE[account].append({
        'ok': ok,
        'ts': now
    })


def is_allowed(account: str, now: float) -> bool:
    if account not in STORAGE:
        return True
    failure_counts = 0
    for rec in STORAGE[account][::-1]:
        if rec['ts'] >= now - WINDOW_INTEREVAL_MS:
            if not rec['ok']:
                failure_counts += 1
        else:
            break

    return failure_counts < WINDOW_SIZE


if __name__ == "__main__":
    STORAGE.clear()
    account = "test_user"
    t0 = 1000

    print("=== Демонстрація та перевірка Edge Cases (auth/lockout.py) ===")

    # Edge Case 1: Новий акаунт без записів
    print(f"1. Новий акаунт: is_allowed = {is_allowed(account, t0)}")
    assert is_allowed(account, t0) is True

    # Edge Case 2: Рівно 4 помилки (межа дозволеного: N = WINDOW_SIZE - 1)
    for i in range(4):
        record_attempt(account, False, t0 + i * 1000)
    print(f"2. Після 4 помилок (межа 4 < 5): is_allowed = {is_allowed(account, t0 + 4000)}")
    assert is_allowed(account, t0 + 4000) is True

    # Edge Case 3: 5-а помилка (рівно на межі ліміту: N = WINDOW_SIZE)
    record_attempt(account, False, t0 + 4000)
    print(f"3. Після 5-ї помилки (межа 5 == 5): is_allowed = {is_allowed(account, t0 + 4000)}")
    assert is_allowed(account, t0 + 4000) is False

    # Edge Case 4: Точно на часовій межі вікна (ts >= now - W)
    t_edge = t0 + WINDOW_INTEREVAL_MS
    print(f"4. Рівно на межі вікна (t = {t_edge}): is_allowed = {is_allowed(account, t_edge)}")
    assert is_allowed(account, t_edge) is False

    # Edge Case 5: Одразу за межею вікна (+1 мс) — перша спроба вибуває
    t_after = t0 + WINDOW_INTEREVAL_MS + 1
    print(f"5. Одразу за межею (+1 мс, t = {t_after}): is_allowed = {is_allowed(account, t_after)}")
    assert is_allowed(account, t_after) is True

    print("=== Усі Edge Cases успішно пройдено! ===")