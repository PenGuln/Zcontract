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

3. Deploy your Smart Contract

```
brownie run .\scripts\deploy.py --network your-network
```
4. Run tests
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

Interface.
