from brownie import network, config, accounts, MockV3Aggregator
import time
import random
import hashlib

LOCAL_BLOCKCHAIN_ENVIRONMENTS = ["development", "ganache-local"]
# prime field
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# generator h in Extension Fields p^4
H = [20631701070564089795189224372619497824086557585330667913427275589301710430512, 
     9429379164803497793026054781534592256781010836706888356722091836870089770555,
     10402993867668193033541051208706584610682031083288448098221649106394706629532,
     5758654313295298584809221016113927472241335141333248692396291700325901514347]
     
# irreducible polynomial P(x) = x^4-w
W = 1000000007

def get_account():
    if (network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS):
        return accounts[0]
    else:
        return accounts.add(config["wallets"]["from_key"])

def deploy_mocks():
    print(f"The active network is {network.show_active()}")
    print("Deploying Mocks...")
    if len(MockV3Aggregator) <= 0:
        MockV3Aggregator.deploy(8, 200000000000, {"from": get_account()})
    print("Mocks Deployed!")

def int_to_hex(x: int):
    return ("%08x" % x)

def encodePacked(x, y):
    if (len(x) & 1): x = '0' + x
    if (len(y) & 1): y = '0' + y
    x = bytes.fromhex(x)
    y = bytes.fromhex(y)
    assert(len(x) <= 32)
    assert(len(y) <= 32)
    return bytes(32 - len(x)) + x + bytes(32 - len(y)) + y

def encodePacked1024(a, b, c, d):
    if (len(a) & 1): a = '0' + a
    if (len(b) & 1): b = '0' + b
    if (len(c) & 1): c = '0' + c
    if (len(d) & 1): d = '0' + d
    a = bytes.fromhex(a)
    b = bytes.fromhex(b)
    c = bytes.fromhex(c)
    d = bytes.fromhex(d)
    assert(len(a) <= 32)
    assert(len(b) <= 32)
    assert(len(c) <= 32)
    assert(len(d) <= 32)
    return bytes(32 - len(a)) + a + bytes(32 - len(b)) + b + bytes(32 - len(c)) + c + bytes(32 - len(d)) + d

def hex_to_u32_list(x):
    assert(len(x) % 8 == 0)
    r = []
    n = len(x) // 8
    for i in range(n):
        r.append(int(x[i * 8 : i * 8 + 8], 16))
    return r

def u32_list_to_hex(ls):
    x = ""
    for i in range(len(ls)):
        x = x + int_to_hex(ls[i])
    return x
# Fake generator, just for testing
def gen_key():
    sk = hashlib.sha256(bytes('some secret string' + str(time.time()) + str(random.random()), encoding='utf-8')).digest() 
    pk = hashlib.sha256(sk + bytes(96)).hexdigest()
    sk = sk.hex()
    return pk, sk

def rds():
    return hashlib.sha256(bytes('82c12642a787c2baac970185a503b2b09a4d812fffa1234700f8abe9f8fbabbc' + str(time.time()) + str(random.random()), encoding='utf-8')).hexdigest()

def rdk():
    return hashlib.sha256(bytes('5f06ff0d141d6b1adcbc5bd9fa98c644098f6042ddc77fc1e82aed6804cf15cf' + str(time.time()) + str(random.random()), encoding='utf-8')).hexdigest()[0:32]

def speck_round(x, y, k):
    x = ((x >> 8) | (x << (32 - 8))) & ((1<<32)-1)
    x = (x + y) & ((1<<32)-1)
    x ^= k
    y = ((y << 3) | (y >> (32 - 3))) & ((1<<32)-1)
    y ^= x
    return x, y

def speck_unround(x, y, k):
    y ^= x
    y = ((y >> 3) | (y << (32 - 3))) & ((1<<32)-1)
    x ^= k
    x = (x - y) & ((1<<32)-1)
    x = ((x << 8) | (x >> (32 - 8))) & ((1<<32)-1)
    return x, y

# blocksize: 32bits * 2 
# pt,ct : 64bits * 8 = 512bits
# k : 128bits
def speck_enc(pt, k): 
    pt = hex_to_u32_list(pt)
    k = hex_to_u32_list(k)
    for i in range(8):
        b = k[0]
        a = k[1:]
        for j in range(27):
            pt[i * 2 + 1], pt[i * 2] = speck_round(pt[i * 2 + 1], pt[i * 2], b)
            a[j % 3], b = speck_round(a[j % 3], b, j)
    pt = u32_list_to_hex(pt)
    return pt

def speck_dec(pt, k): 
    pt = hex_to_u32_list(pt)
    k = hex_to_u32_list(k)
    for i in range(8):
        b = k[0]
        a = k[1:]
        for j in range(27):
            a[j % 3], b = speck_round(a[j % 3], b, j)
        for j in range(26, -1, -1):
            a[j % 3], b = speck_unround(a[j % 3], b, j)
            pt[i * 2 + 1], pt[i * 2] = speck_unround(pt[i * 2 + 1], pt[i * 2], b)
    pt = u32_list_to_hex(pt)
    return pt

def mul(a, b):
    c = [0 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            if (i + j <= 3):
                c[(i + j) & 3] += a[i] * b[j]
            else:
                c[(i + j) & 3] += a[i] * b[j] * W
    for i in range(4):
        c[i] = c[i] % P
    return c

def polyPow(a, w):
    y = [1, 0, 0, 0]
    x = a
    for i in range(256):
        if (w & 1): y = mul(y, x)
        x = mul(x, x)
        w >>= 1
    return y

def calcKey(a, b):
    a = polyPow(a, int(b, 16))
    return hashlib.sha256(encodePacked1024("%032x" % a[0], "%032x" % a[1], "%032x" % a[2], "%032x" % a[3])).hexdigest()[0:32]
