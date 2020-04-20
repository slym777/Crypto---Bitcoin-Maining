import hashlib, struct, random, sys

ver = int("0x20400000", 0)
prev_block = "00000000000000000006a4a234288a44e715275f1775b77b2fddb6c02eb6b72f"
mrkl_root = "2dc60c563da5368e0668b81bc4d8dd369639a1134f68e425a9a74e428801e5b8"
time_ = 0x5DB8AB5E
bits = 0x17148EDF

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1 << (8 * (exp - 3))))

nonce1 = 3060331852
nr_try = 100000000
nonce2 = random.randint(nonce1, (sys.maxsize & 0xFFFFFFFF) - nr_try)
print (nonce2)
initial_nonce2 = nonce2

while nonce2 < initial_nonce2 + nr_try:
    header = (struct.pack("<L", ver) + bytearray.fromhex(prev_block)[::-1] +
              bytearray.fromhex(mrkl_root)[::-1] + struct.pack("<LLL", time_, bits, nonce2))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    if hash[::-1] < bytearray.fromhex(target_hexstr):
        print(nonce2, hash.hex()[::-1])
        print('success')
        break
    nonce2 += 1
print ("Nu a fost gasita nici un hash care sa satisfaca dificultatea")