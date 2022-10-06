from brownie import network, config, accounts, MockV3Aggregator
import datetime
import hashlib

LOCAL_BLOCKCHAIN_ENVIRONMENTS = ["development", "ganache-local"]

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

def hextou328(x):
    assert(len(x) == 64)
    r = []
    for i in range(8):
        r.append(int(x[i * 8 : i * 8 + 8], 16))
    return r


# Fake generator, just for testing
def gen_key():
    sk = hashlib.sha256(bytes('some secret string' + str(datetime.datetime.now()), encoding='utf-8')).digest() 
    pk = hashlib.sha256(sk + bytes(96)).hexdigest()
    sk = sk.hex()
    return pk, sk

def rds():
    return hashlib.sha256(bytes('82c12642a787c2baac970185a503b2b09a4d812fffa1234700f8abe9f8fbabbc' + str(datetime.datetime.now()), encoding='utf-8')).hexdigest()