from base64 import encode
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

def init_new_wallet(name: str):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    if (not name in wallets):
        pk, sk = gen_key()
        _, esk = gen_key()
        epk = polyPow(H, int(esk, 16))
        wallets[name] = {
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
        print("duplicate name")

def clean_wallet(name : str):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    if (name in wallets):
        wallets[name] = {
            "pk": wallets[name]["pk"],
            "sk": wallets[name]["sk"],
            "epk" : wallets[name]["epk"],
            "esk" : wallets[name]["esk"],
            "coins": [],
            "spentcoins": [],
            "freezecoins" : []
        }
        with open('.\wallets.json', 'w') as f:
            json.dump(wallets, f)
        f.close()
    else:
        print("name not found")

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


def mint(name: str, value : int):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(name in wallets)
    pk = wallets[name]['pk']
    s = rds()
    account = get_account()
    cash = Hawk[-1]
    tx = cash.mint(pk, s, {"from": account, "value": value})
    wallets[name]["coins"].append({
        "s" : s,
        "val" : value,
        "sel": tx.return_value
    })

    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()
    return s


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
    cash = Hawk[-1]
    root = cash.hashes(1).hex()
    branch = cash.getBranch(sel)

    sk = wallets[name]['sk']
    pk = wallets[name]['pk']
    pk1 = wallets[name1]['pk']
    pk2 = wallets[name2]['pk']

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
    wallets[name]['spentcoins'].append(s)
    wallets[name1]['coins'].append({
        "s" : s1,
        "val" : val1,
        "sel": cash.cur()-2 # need to be fixed
    })

    wallets[name2]['coins'].append({
        "s" : s2,
        "val" : val2,
        "sel": cash.cur()-1 # need to be fixed
    })

    with open('.\wallets.json', 'w') as f:
        json.dump(wallets, f)
    f.close()
    return s1, s2


def freeze(name, s, indata):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(name in wallets)
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

    account = get_account()
    cash = Hawk[-1]
    root = cash.hashes(1).hex()
    branch = cash.getBranch(sel)

    sk = wallets[name]['sk']
    pk = wallets[name]['pk']

    coin = hashlib.sha256(encodePacked(s, int_to_hex(val))).hexdigest()
    s_ = rds()
    k = rdk()
    sn = hashlib.sha256(encodePacked1024(sk, '0', pk, coin)).hexdigest()
    cm_ = hashlib.sha256(encodePacked(s_, k + int_to_hex(indata) + int_to_hex(val))).hexdigest()
    freeze_generate_proof(root, sn, cm_, pk, sk, branch, sel, s, val, indata, k, s_)
    with open('.\proof.json') as f:
        proof = json.load(f)
    tx = cash.freeze(list(proof['proof'].values()), pk, sn, cm_, {"from": account})

    wallets[name]['spentcoins'].append(s)
    wallets[name]['freezecoins'].append({
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

def compute(name, s, manager):
    with open('.\wallets.json', 'r') as f:
        wallets = json.load(f)
    f.close()

    assert(name in wallets)
    freezecoins = wallets[name]['freezecoins']
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
    epk = wallets[manager]['epk']
    k_ = calcKey(epk, wallets[name]['esk'])
    ct = speck_enc(pt, k_) # symmetric encrypion

    compute_generate_proof(epk, cm, ct, val, indata, k, s, wallets[name]['esk'])
    with open('.\proof.json') as f:
        proof = json.load(f)
    
    tx = cash.compute(list(proof['proof'].values()), cm, [ct[:64], ct[64:]], {"from": account})

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

    epk = wallets['siqi']['epk'] # should be stored in contract instead
    k_ = calcKey(epk, wallets[manager]['esk'])

    for i in range(2):
        p, cmt, ctH, ctL = cash.freezeCoins(i)
        pt = speck_dec((ctH + ctL).hex(), k_)
        print(pt)
        if (int.from_bytes(ctH, 'big') == 0 and int.from_bytes(ctL, 'big') == 0) : 
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
        _s.append(rs)
        _coin.append(hashlib.sha256(encodePacked(rs, int_to_hex(out_val[i]))).hexdigest())
        ct.append(speck_enc(rs + int_to_hex(0) * 7 + int_to_hex(out_val[i]),  k[i]))  # symmetric encrypion

    finalize_generate_proof(out, cm, _coin, ct, s, val, indata, k, _s)
    with open('.\proof.json') as f:
        proof = json.load(f)
    tx = cash.finalize(list(proof['proof'].values()), out, _coin, [[ct[0][:64], ct[0][64:]],[ct[1][:64], ct[1][64:]]], {"from": account})
    
def main():
    #init_new_wallet("siqi")
    #clean_wallet("siqi")
    #s = mint("siqi", 1000000)
    #s1, s2 = pour("siqi", s, "siqi", 600000, "siqi", 400000)
    #s3 = freeze("siqi", s1, 1)
    #s4 = freeze("siqi", s2, 2)
    #compute("siqi", "1294baf117fd2449e3a889a980ccd86b29ec5fbe2db5deb2d11f6e51828eede6", "siqi")
    #compute("siqi", "d54c2a8871db8d026c646859a53b16d7fa699247e3b8da2f8e6b7322bb31f4a0", "siqi")
    finalize("siqi")
