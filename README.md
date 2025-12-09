

#  Private Delegate Voting (ZK + ElGamal + Merkle)

A **privacy-preserving delegate voting system** built using:

* **ElGamal homomorphic encryption**
* **Zero-knowledge SNARK proofs (Circom + SnarkJS)**
* **Merkle tree membership verification**
* **Solidity smart contracts**
* **Private delegation+ verifiable tally decryption**

---
##  System Overview

This system allows participants to:

*  vote using **encrypted ballots**
* Prove correctness of their vote delegation using **ZK proofs**
* Register as delegates using 
* Aggregate encrypted votes on-chain using **homomorphic addition**
* Verify the final decryptions with **ZK decryption proofs**
##  Architecture
```
Admin ───────► electionSetup()
                 │
                 ▼
           Smart Contract
        ┌──────────────────┐
        │ Merkle Root      │
        │ Public Key       │
        │ Encrypted Votes  │◄───── Voters (ElGamal + ZK)
        │ Homomorphic Sum  │
        └──────────────────┘
                 │
                 ▼
        decryptTally() ◄──── Decryptors (Trusted Authority)
```
##  Actors and role 

| Actor              | Role                                                |
| ------------------ | --------------------------------------------------- |
| **Admin**          | Creates election, sets Merkle root & public key     |
| **Delegate**       | Registers using ZK proof                      |
| **Voter**          | Encrypts vote + submits zkSNARK proof               |
| **Decryptor**      | This is done by the Trusted Authority    |
| **Smart Contract** | Verifies proofs, stores ciphertexts, enforces rules |

---

### 1 Setup

Admin configures election:

* Merkle root of delegates
* ElGamal public key
  

**Solidity:**
`electionSetup(bytes32 root, PubKey pubkey, address)`

---

### 2 Delegate Registration

Delegate submits  proof to register and that the ciphertext is correctly generated . The delegates might also choose to unregister 

---
### 3 Delegation 
Delegate delegates his/her votes privately to other delegates, there is a proof of correct delegation to ensure that the vote is delegated correctly

### 4 Voting

The votes is encrypted using elgammal proof as a ciphertext :

* Vote is valid (yes/no/abstain)
* We check again if the ciphertext is correctly formed 
  

**Solidity:**
`vote(Ciphertext ct, bytes proof, ...)`

---

### 5 Tallying

Contract homomorphically adds ciphertexts.

**Solidity:**
`_add()` (internal)
---

### 6 Decryption
 This should be done by the Trusted Authority.
**Solidity:**
`decryptTally(bytes32[3] percents, bytes proof)`
---

## Project Structure

```
project/
│
├── contracts/
│   ├── DelegateVoting.sol

│   ├── DelegateRegistry.sol
│   └── Token.sol
│
├── circom/
│   ├── ciphertext.circom
│   ├── delegation.circom
│   ├── merkle.circom
│   └── inputs/input.json
│
├── build/
│   └── ciphertext_js/
│       ├── generate_witness.js
│       ├── witness_calculator.js
│       ├── *.wasm
│

## 🔧 Interacting With the Contracts
### Delegate Registration
```solidity
delegateRegistration(proof);
```
### Submit Vote

```solidity
vote(
    ct,
    proof,
    message,
    randomness,
    support,     // 0 = No, 1 = Yes, 2 = Abstain
    root,
    proposalID
);
```
### Decrypt Tally

```solidity
decryptTally(percents, proof);
```
##  Features

* Private encrypted voting
* ZK-proof verification on-chain
* Homomorphic tally computation
* Verifiable decryption
---
