from rsa_edu import fast_pow_mod, is_probable_prime, egcd, modinv, keygen, encrypt, decrypt
 
val, steps = fast_pow_mod(7, 13, 100)
print(val)                       # очікується 7  (бо 7^4 ≡ 1 mod 100)
for s in steps:
    print(s)                     # протокол «квадрат і множення»
 
print(is_probable_prime(7919))   # True  — просте
print(is_probable_prime(7917))   # False — складене
print(egcd(240, 46))             # (2, ...) — НСД дорівнює 2
print(modinv(17, 3120))          # 2753 — обернений до 17 за модулем 3120

p = 61
q = 53
e = 17
n = p * q
phi = (p-1)*(q-1)
print(n, phi)
d = modinv(e, phi)
m = 65
c = encrypt(m, e, n)
assert c == 2790
assert decrypt(c, d, n) == 65

 
k = keygen(bits=28)          # bits — розрядність КОЖНОГО множника
print(k["p"], k["q"], k["n"], k["e"], k["d"])
val = k['e'] * k['d'] % k['phi']
print(val)
assert val == 1
m = 42
c = encrypt(m, k["e"], k["n"])
assert decrypt(c, k["d"], k["n"]) == m
assert is_probable_prime(k['p'])
assert is_probable_prime(k['q'])
assert k['p'].bit_length() == 28