# zcontract

#### Introduction
This project is an implemention of Hawk, and contains a example of privacy-preserving Rock Scissor and Paper smart contract.

you can read the paper of Hawk here https://eprint.iacr.org/2015/675.pdf. 

The NIZK part is realized by Zokrates, a toolbox for zkSNARKs on Ethereum 

#### How to use
1. Install Brownie

```
pipx install eth-brownie
```

2. Install Zokrates

See https://github.com/Zokrates/ZoKrates

3. Compile your circuits
```
zokrates compile -i .\zokrates\pour.zok -o .\zokrates\pour
zokrates compile -i .\zokrates\freeze.zok -o .\zokrates\freeze
zokrates compile -i .\zokrates\compute.zok -o .\zokrates\compute
zokrates compile -i .\zokrates\finalize.zok -o .\zokrates\finalize
```

4. Setup
```
zokrates setup -i .\zokrates\pour -p .\keys\pour_proving.key -v  .\keys\pour_verification.key
zokrates setup -i .\zokrates\freeze -p .\keys\freeze_proving.key -v .\keys\freeze_verification.key
zokrates setup -i .\zokrates\compute -p .\keys\compute_proving.key -v .\keys\compute_verification.key
zokrates setup -i .\zokrates\finalize -p .\keys\finalize_proving.key -v .\keys\finalize_verification.key
```

5. Export verifier
```
zokrates export-verifier -i .\keys\pour_verification.key -o .\contracts\pour.sol
zokrates export-verifier -i .\keys\freeze_verification.key -o .\contracts\freeze.sol
zokrates export-verifier -i .\keys\compute_verification.key -o .\contracts\compute.sol
zokrates export-verifier -i .\keys\finalize_verification.key -o .\contracts\finalize.sol
```

6. Copy Codes

Copy the main part of each verifier, and paste it to CashBase.sol.

7. Deploy your Smart Contract

```
brownie run .\scripts\deploy.py --network your-network
```
8. Run tests
```
brownie run .\scripts\main.py --network your-network
```
#### Parameters

For PRFs and commitments, we use SHA-256

Diffie-Hellman key exchange: public key operations is performed in a SNARK-friendly prime-order subgroup of the Galois field extension, where µ=4, p is a 254-bit prime (see details in utils.py)

symmetric encryption: Speck (64/128, 27 rounds)

#### Evaluation

|  Primitives  | circuit constraints |
|  ----  | ----  |
| mint | - |
| pour | 1034450 |
| freeze | 986435 |
| compute | 163711 |
| finalize | 231069 |

#### Future work

Improve the Key generation.

Optimize in advance.

More convenient setup, decoupling.

Interface.
