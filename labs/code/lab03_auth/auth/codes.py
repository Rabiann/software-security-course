import hmac
import random

SELECT_SET = '1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def generate_codes(count: int) -> set[str]:
    codes = set()
    while len(codes) < count:
        part1 = ''.join(random.choice(SELECT_SET) for _ in range(4))
        part2 = ''.join(random.choice(SELECT_SET) for _ in range(4))
        codes.add(f"{part1}-{part2}")
    return codes

CODES = generate_codes(10)

def validate(code: str) -> bool:
    success = False
    for stored in list(CODES):
        if hmac.compare_digest(stored, code):
            CODES.remove(stored)
            success = True
    return success

if __name__ == "__main__":
    print(CODES)