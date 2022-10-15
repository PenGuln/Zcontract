from brownie import Hawk
from scripts.utils import (
    get_account, 
    encodePacked, 
    encodePacked1024, 
    gen_key, 
    hex_to_u32_list,
    int_to_hex,
    rds,
    rdk,
    speck_enc,
    speck_dec,
    polyPow,
    calcKey,
    P, H
)
from scripts.contractPriv import RSP
import hashlib
import subprocess
import json

def init_new_wallet(user: str):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    if (not user in wallets):
        pk, sk = gen_key()
        _, esk = gen_key()
        epk = polyPow(H, int(esk, 16))
        wallets[user] = {
            "pk": pk,
            "sk": sk,
            "epk" : epk,
            "esk" : esk,
            "coins": [],
            "spentcoins": [],
            "freezecoins" : []
        }
        with open('.\wallets.json', 'w') as f:
            json.dump(wallets, f)
        f.close()
    else:
        print("duplicate user")

def clean_wallet(user : str):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    if (user in wallets):
        wallets[user] = {
            "pk": wallets[user]["pk"],
            "sk": wallets[user]["sk"],
            "epk" : wallets[user]["epk"],
            "esk" : wallets[user]["esk"],
            "coins": [],
            "spentcoins": [],
            "freezecoins" : []
        }
        with open('.\wallets.json', 'w') as f:
            json.dump(wallets, f)
        f.close()
    else:
        print("user not found")

def pour_generate_proof(root, sn, coin1, coin2, 
                        pk, sk, 
                        branch, sel, 
                        s, val, 
                        s1, val1, 
                        s2, val2):
    data = hex_to_u32_list(root + sn + coin1 + coin2 + pk + sk)
    for i in range(8):
        data += hex_to_u32_list(branch[i].hex())
    for i in range(8):
        data += [sel & 1]
        sel >>= 1
    data += hex_to_u32_list(s) + [val] + \
                  hex_to_u32_list(s1) + [val1] + \
                  hex_to_u32_list(s2) + [val2]
    data = [str(x) for x in data]
    print("generating proof...")
    zok = subprocess.run(["zokrates", "compute-witness", "--verbose", "-i", ".\zokrates\pour", "-a"] + data, capture_output = True)
    print(zok)
    zok = subprocess.run(["zokrates", "generate-proof", "-i", ".\zokrates\pour", "-p", ".\keys\pour_proving.key"], capture_output = True)
    print(zok)
    print("proof generated")

def freeze_generate_proof(root, sn, cm_, pk, sk, branch, sel, s, val, indata, k, s_):
    data = hex_to_u32_list(root + sn + cm_ + pk + sk)
    for i in range(8):
        data += hex_to_u32_list(branch[i].hex())
    for i in range(8):
        data += [sel & 1]
        sel >>= 1
    data += hex_to_u32_list(s) + [val] + [indata] + hex_to_u32_list(k + s_)
    data = [str(x) for x in data]
    print("generating proof...")
    zok = subprocess.run(["zokrates", "compute-witness", "--verbose", "-i", ".\zokrates\\freeze", "-a"] + data, capture_output = True)
    print(zok)
    zok = subprocess.run(["zokrates", "generate-proof", "-i", ".\zokrates\\freeze", "-p", ".\keys\\freeze_proving.key"], capture_output = True)
    print(zok)
    print("proof generated")

def compute_generate_proof(epk, cm, ct, val, indata, k, s, esk) :
    data = epk + hex_to_u32_list(cm + ct) + [val] + [indata] + hex_to_u32_list(k + s + esk)
    data = [str(x) for x in data]
    print("generating proof...")
    zok = subprocess.run(["zokrates", "compute-witness", "--verbose", "-i", ".\zokrates\\compute", "-a"] + data, capture_output = True)
    print(zok)
    zok = subprocess.run(["zokrates", "generate-proof", "-i", ".\zokrates\\compute", "-p", ".\keys\\compute_proving.key"], capture_output = True)
    print(zok)
    print("proof generated")

def finalize_generate_proof(out, cm, coin_, ct, s, val, indata, k, s_):
    data = [out] + hex_to_u32_list(cm[0] + cm[1] + coin_[0] + coin_[1] + ct[0] + ct[1] + s[0] + s[1]) + val + indata + hex_to_u32_list(k[0] + k[1] + s_[0] + s_[1])
    data = [str(x) for x in data]
    print("generating proof...")
    zok = subprocess.run(["zokrates", "compute-witness", "--verbose", "-i", ".\zokrates\\finalize", "-a"] + data, capture_output = True)
    print(zok)
    zok = subprocess.run(["zokrates", "generate-proof", "-i", ".\zokrates\\finalize", "-p", ".\keys\\finalize_proving.key"], capture_output = True)
    print(zok)
    print("proof generated")


def mint(user: str, value : int):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(user in wallets)
    pk = wallets[user]['pk']
    s = rds()
    account = get_account()
    cash = Hawk[-1]
    tx = cash.mint(pk, s, {"from": account, "value": value})
    wallets[user]["coins"].append({
        "s" : s,
        "val" : value,
        "sel": tx.return_value
    })

    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()
    return s


def pour(user, s, user1, val1, user2, val2):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(user in wallets)
    assert(user1 in wallets)
    assert(user2 in wallets)
    coins = wallets[user]['coins']
    spentcoins = wallets[user]['spentcoins']
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
    cash = Hawk[-1]
    root = cash.hashes(1).hex()
    branch = cash.getBranch(sel)

    sk = wallets[user]['sk']
    pk = wallets[user]['pk']
    pk1 = wallets[user1]['pk']
    pk2 = wallets[user2]['pk']

    coin = hashlib.sha256(encodePacked(s, int_to_hex(val))).hexdigest()
    s1 = rds()
    s2 = rds()
    coin1 = hashlib.sha256(encodePacked(s1, int_to_hex(val1))).hexdigest()
    coin2 = hashlib.sha256(encodePacked(s2, int_to_hex(val2))).hexdigest()
    sn = hashlib.sha256(encodePacked1024(sk, '0', pk, coin)).hexdigest()
    pour_generate_proof(root, sn, coin1, coin2, 
                        pk, sk, 
                        branch, sel, 
                        s, val, 
                        s1, val1, 
                        s2, val2)
    with open('.\proof.json') as f:
        proof = json.load(f)
    tx = cash.pour(list(proof['proof'].values()), sn, pk1, coin1, pk2, coin2, {"from": account})
    wallets[user]['spentcoins'].append(s)
    wallets[user1]['coins'].append({
        "s" : s1,
        "val" : val1,
        "sel": cash.cur()-2 # need to be fixed
    })

    wallets[user2]['coins'].append({
        "s" : s2,
        "val" : val2,
        "sel": cash.cur()-1 # need to be fixed
    })

    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()
    return s1, s2


def freeze(user, s, indata):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(user in wallets)
    coins = wallets[user]['coins']
    spentcoins = wallets[user]['spentcoins']
    flag = False
    for coin in coins:
        if (coin['s'] == s): 
            flag = True
            val = coin['val']
            sel = coin['sel']
    assert(flag)
    assert(not s in spentcoins)

    account = get_account()
    cash = Hawk[-1]
    root = cash.hashes(1).hex()
    branch = cash.getBranch(sel)

    sk = wallets[user]['sk']
    pk = wallets[user]['pk']

    coin = hashlib.sha256(encodePacked(s, int_to_hex(val))).hexdigest()
    s_ = rds()
    k = rdk()
    sn = hashlib.sha256(encodePacked1024(sk, '0', pk, coin)).hexdigest()
    cm_ = hashlib.sha256(encodePacked(s_, k + int_to_hex(indata) + int_to_hex(val))).hexdigest()
    freeze_generate_proof(root, sn, cm_, pk, sk, branch, sel, s, val, indata, k, s_)
    with open('.\proof.json') as f:
        proof = json.load(f)
    tx = cash.freeze(list(proof['proof'].values()), pk, sn, cm_, {"from": account})

    wallets[user]['spentcoins'].append(s)
    wallets[user]['freezecoins'].append({
        "in" : indata,
        "cm" : cm_,
        "val" : val,
        "s" : s_,
        "k" : k
    })
    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()
    return s_

def compute(user, s):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(user in wallets)
    freezecoins = wallets[user]['freezecoins']
    flag = False
    for coin in freezecoins:
        if (coin['s'] == s): 
            flag = True
            val = coin['val']
            indata = coin['in']
            cm = coin['cm']
            k = coin['k']
    assert(flag)

    account = get_account()
    cash = Hawk[-1]
    pt = int_to_hex(0) + int_to_hex(0) + s + k + int_to_hex(indata) + int_to_hex(val)
    epk = list(cash.getEpk()) # fetch the manager's epk from smart contract
    k_ = calcKey(epk, wallets[user]['esk'])
    ct = speck_enc(pt, k_)    # symmetric encrypion

    compute_generate_proof(epk, cm, ct, val, indata, k, s, wallets[user]['esk'])
    with open('.\proof.json') as f:
        proof = json.load(f)
    
    tx = cash.compute(list(proof['proof'].values()), cm, [ct[:64], ct[64:]], wallets[user]['epk'], {"from": account})

def finalize(manager):
    account = get_account()
    cash = Hawk[-1]
    val = []
    indata = []
    k = []
    s = []
    cm = []
    
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()
   
    for i in range(2):
        p, cmt, ctH, ctL, epk = cash.getFreezeItem(i)  # fetch the users' epk from smart contract (It's only avaliable for those called compute)
        k_ = calcKey(list(epk), wallets[manager]['esk'])
        pt = speck_dec((ctH + ctL).hex(), k_)  # symmetric decryption (speck)
        if (int.from_bytes(ctH, 'big') == 0 and int.from_bytes(ctL, 'big') == 0) : # not called compute
            val.append(0)
            indata.append(0)
            k.append(0)
            s.append(0)
            cm.append(0)
        else:
            val.append(int(pt[120 : 128], 16))
            indata.append(int(pt[112 : 120], 16))
            k.append(pt[80: 112])
            s.append(pt[16: 80])
            cm.append(cmt.hex())

    out_val, out = RSP(val, indata) # execute the private contract

    _s = []
    _coin = []
    ct = []
    for i in range(2):
        rs = rds()
        _s.append(rs)                                                                         # sample randomness
        _coin.append(hashlib.sha256(encodePacked(rs, int_to_hex(out_val[i]))).hexdigest()) 
        ct.append(speck_enc(rs + int_to_hex(0) * 7 + int_to_hex(out_val[i]),  k[i]))          # symmetric encrypion of the info of the new coin

    finalize_generate_proof(out, cm, _coin, ct, s, val, indata, k, _s)
    with open('.\proof.json') as f:
        proof = json.load(f)
    tx = cash.finalize(list(proof['proof'].values()), out, _coin, [[ct[0][:64], ct[0][64:]],[ct[1][:64], ct[1][64:]]], {"from": account})

def withdraw(user):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()
    assert(user in wallets)
    cash = Hawk[-1]
    for i in range(2):
        pk = cash.getFreezeItem(i)[0].hex()
        cm = cash.getFreezeItem(i)[1].hex()
        flag = False
        for coin in wallets[user]['freezecoins']:
            if (coin['cm'] == cm): 
                flag = True
                k = coin['k']
        if (flag):
            ct = cash.getFreezeItem(i)[2].hex() +  cash.getFreezeItem(i)[3].hex()
            pt = speck_dec(ct, k)
            sel = cash.getFreezeItem(i)[4][0]
            wallets[user]['coins'].append({
                "s" : pt[0:64],
                "val" : int(pt[120:128], 16),
                "sel": sel
            })

    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()

def main():
    init_new_wallet("Alice")
    init_new_wallet("Bob")
    init_new_wallet("Manager")
    clean_wallet("Alice")
    clean_wallet("Bob")
    clean_wallet("Manager")
    s1 = mint("Alice", 1000000)
    s2 = mint("Bob", 500000)
    s3, s4 = pour("Alice", s1, "Bob", 300000, "Alice", 700000)
    s5 = freeze("Bob", s3, 1) # Bob freeze the coin s3 with value 300000 and in = 1 (paper)
    s6 = freeze("Alice", s4, 2)  # Bob freeze the coin s4 with value 700000 and in = 2 (scissor)
    compute("Alice", s6) 
    compute("Bob", s5)
    finalize("Manager")
    withdraw('Alice')
    withdraw('Bob')
   