from brownie import Cash, Verifier, config
from scripts.helpful_scripts import (
    get_account, 
    encodePacked, 
    encodePacked1024, 
    gen_key, 
    hextou328, 
    rds
)
import hashlib
import subprocess
import json

def mint(name: str, value : int):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(name in wallets)
    pk = wallets[name]['pk']
    s = rds()
    account = get_account()
    cash = Cash[-1]
    tx = cash.mint(pk, s, {"from": account, "value": value})
    wallets[name]["coins"].append({
        "s" : s,
        "val" : value,
        "sel": tx.return_value
    })

    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()

def pour_generate_proof(root, sn, p1, coin1, p2, coin2, 
                        pk, sk, 
                        branch, sel, 
                        s, val, 
                        s1, val1, 
                        s2, val2):
    data = hextou328(root) + hextou328(sn) + hextou328(p1) + hextou328(coin1) + hextou328(p2) + hextou328(coin2) + \
           hextou328(pk) + hextou328(sk)
    for i in range(8):
        data += hextou328(branch[i].hex())
    for i in range(8):
        data += [sel & 1]
        sel >>= 1
    data = data + hextou328(s) + [val] + \
                  hextou328(s1) + [val1] + \
                  hextou328(s2) + [val2]
    data = [str(x) for x in data]
    print("generating proof...")
    zok = subprocess.run(["zokrates", "compute-witness", "--verbose", "-i", ".\zokrates\pour", "-a"] + data, capture_output = True)
    print(zok)
    zok = subprocess.run(["zokrates", "generate-proof", "-i", ".\zokrates\pour"], capture_output = True)
    print(zok)
    print("proof generated")

def pour(name, s, name1, val1, name2, val2):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(name in wallets)
    assert(name1 in wallets)
    assert(name2 in wallets)
    coins = wallets[name]['coins']
    spentcoins = wallets[name]['spentcoins']
    flag = False
    for coin in coins:
        if (coin['s'] == s): 
            flag = True
            val = coin['val']
            sel = coin['sel']
    assert(flag)
    assert(not s in spentcoins)

    assert(val == val1 + val2)
    account = get_account()
    cash = Cash[-1]
    root = cash.hashes(1).hex()
    #print(cash.cur())
    branch = cash.getBranch(sel)

    sk = wallets[name]['sk']
    pk = wallets[name]['pk']
    pk1 = wallets[name1]['pk']
    pk2 = wallets[name2]['pk']

    coin = hashlib.sha256(encodePacked(s, hex(val)[2:])).hexdigest()
    s1 = rds()
    s2 = rds()
    coin1 = hashlib.sha256(encodePacked(s1, hex(val1)[2:])).hexdigest()
    coin2 = hashlib.sha256(encodePacked(s2, hex(val2)[2:])).hexdigest()
    sn = hashlib.sha256(encodePacked1024(sk, '0', pk, coin)).hexdigest()
    pour_generate_proof(root, sn, pk1, coin1, pk2, coin2, 
                        pk, sk,
                        branch, sel, 
                        s, val,
                        s1, val1,
                        s2, val2)
    
    with open('.\proof.json') as f:
        proof = json.load(f)
    tx = cash.pour(list(proof['proof'].values()), sn, pk1, coin1, pk2, coin2, {"from": account})

    wallets[name]['spentcoins'].append(s)
    wallets[name1]['coins'].append({
        "s" : s1,
        "val" : val1,
        "sel": 0 # need to be fixed
    })

    wallets[name2]['coins'].append({
        "s" : s2,
        "val" : val2,
        "sel": 0 # need to be fixed
    })

    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()

def init_new_wallet(name: str):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    if (not name in wallets):
        pk, sk = gen_key()
        wallets[name] = {
            "pk": pk,
            "sk": sk,
            "coins": [],
            "spentcoins": []
        }
        with open('.\wallets.json', 'w') as f:
            json.dump(wallets, f)
        f.close()
    else:
        print("duplicate name")

def main():
    mint("siqi", 1000000)
    pour("siqi", "971266ae6dd9552954d5e98bcd2d0279534022268570983f2c2eb7025fcc3f43", "alice", 600000, "bob", 400000)