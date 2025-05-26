# Million Message Attack on PKCS#1 v1.5

This project demonstrates a real-world cryptographic vulnerability: **Million Message Attack** against the RSA encryption scheme using the **PKCS#1 v1.5** padding format. It was developed as an academic project and serves as a detailed educational resource on how cryptographic protocols can fail in practice due to seemingly minor leaks.


---

##  Overview

Million Message Attack also known as Bleichenbacher's attack, discovered in 1998, allows an attacker to decrypt RSA ciphertexts without access to the private key. It takes advantage of how certain implementations of the PKCS#1 v1.5 padding scheme respond to improperly padded messages. These responses reveal whether the decrypted message starts with specific padding bytes (`0x00 0x02`), which can be used as an **oracle** in an adaptive attack.

---

##  PKCS#1 v1.5 Padding Scheme

The encoding scheme used prior to encryption is:
EM = 0x00 | 0x02 | PS | 0x00 | M


Where:
- `0x00` is a required starting byte.
- `0x02` signals encryption padding.
- `PS` is a padding string of **non-zero random bytes** (at least 8 bytes).
- `0x00` is a delimiter.
- `M` is the actual message.

The total length of the encoded message **must match** the RSA modulus size in bytes (`k`). Hence, the actual message length is restricted to `k - 11` bytes.

---

##  RSA Implementation Details

RSA key generation and encryption/decryption are implemented from scratch.

- **Modulus (n)**: 256 bits (p, q = 128 bits each)
- **Public Exponent (e)**: 3
- **Private Exponent (d)**: Computed as modular inverse of `e` modulo φ(n)

Example:
n = p * q
φ(n) = (p - 1)(q - 1)
d ≡ e⁻¹ mod φ(n)

Libraries used:
- `gmpy2.is_prime()` for fast prime generation
- Custom modular arithmetic and conversion functions in `utils.py`

---

##  Attack Description

The attack simulates a **padding oracle** that reveals whether a decrypted ciphertext is PKCS#1 conformant. Using this oracle, the attack proceeds in **three main phases** (not counting optional blinding):

### Step-by-Step Process

1. **Initialization**:
   - Let `c` be the intercepted ciphertext.
   - Let `B = 2^(8 * (k - 2))` (defines bounds for conformant messages).
   - Set initial interval `M = [2B, 3B - 1]`.

2. **Searching for PKCS-conforming plaintexts**:
   - Find `s1` such that `c' = (c * s1^e) mod n` is PKCS-conformant.
   - Narrow the intervals of possible plaintext values based on the response.

3. **Iterative Refinement**:
   - If multiple intervals remain: increment `s` linearly.
   - If one interval remains: calculate a range of `s` values that might yield conforming plaintexts using known bounds.
   - Update the intervals after every successful query using modular arithmetic.

4. **Termination**:
   - When the interval converges to a single integer `a`, the plaintext is `m = a mod n`.

---

##  Theory Behind the Attack

The attack exploits the RSA malleability property: for a ciphertext `c = m^e mod n`, any `c' = (c * s^e) mod n` decrypts to `m' = (m * s) mod n`.

Given an oracle that returns whether `m'` is PKCS#1-conformant:
- Each query reveals whether `m * s mod n` falls in `[2B, 3B - 1]`.
- The attacker uses this to iteratively shrink the possible values of `m`.

Bleichenbacher showed that, on average, only about **2^20 queries** are needed to decrypt a ciphertext.

---

##  Project Structure

```bash
.
├── main.py         # Main attack logic
├── rsa.py          # RSA key generation, encryption, decryption
├── utils.py        # Number conversion, primality testing, modular arithmetic
└── requirements.txt # Installation requirements
```
---
##  How to Run

### 🔧 1. Clone the Repository
```bash
git clone https://github.com/NigarHajiyeva/Million-Message-Attack-on-PKCS-1-v1.5.git
cd Million-Message-Attack-on-PKCS-1-v1.5
```
###  2. Install Dependencies
Make sure Python 3 is installed, then run:
```bash
pip install -r requirements.txt
```
###  3. Run a Single Test
To run the attack, execute:
```bash
python3 main.py
```
---
##  References

1. **Daniel Bleichenbacher**, *Chosen ciphertext attacks against protocols based on the RSA encryption standard PKCS #1*, Advances in Cryptology — CRYPTO ’98, Lecture Notes in Computer Science, vol 1462, pp. 1–12, Springer, 1998.  
   🔗 [https://doi.org/10.1007/BFb0055716](https://doi.org/10.1007/BFb0055716)

2. **RFC 2313**, *PKCS #1: RSA Encryption Version 1.5* (Historic RFC).  
   🔗 [https://datatracker.ietf.org/doc/html/rfc2313](https://datatracker.ietf.org/doc/html/rfc2313)
3. **RSA Data Security, Inc.**, *PKCS #1: RSA Encryption Standard*, Version 1.5, Redwood City, CA, November 1993. 


