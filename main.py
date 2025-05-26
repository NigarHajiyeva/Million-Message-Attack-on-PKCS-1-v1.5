import os
import random
import time
from collections import namedtuple

import rsa
import utils

Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])


class PKCS1:
    """
    Handles PKCS#1 v1.5 padding and unpadding.
    """

    def __init__(self, total_bytes):
        self.total_bytes = total_bytes

    def encode(self, message):
        if len(message) > self.total_bytes - 11:
            raise Exception("Message too big for encoding scheme!")

        pad_len = self.total_bytes - 3 - len(message)
        padding = bytes(random.sample(range(1, 256), pad_len))
        encoded = b"\x00\x02" + padding + b"\x00" + message
        return encoded

    def decode(self, encoded):
        encoded = encoded[2:]
        idx = encoded.index(b"\x00")
        message = encoded[idx + 1 :]
        return message


class RSAOracle:
    """
    Represents the RSA setup and oracle for Bleichenbacher attack.
    Only oracle function can use the secret key.
    """

    def __init__(self, modulus_size=256):
        self.modulus_size = modulus_size
        self.pk, self.sk = rsa.generate_key(self.modulus_size)
        self.n, self.e = self.pk
        self.k = modulus_size // 8
        self.queries = 0
        self.t_start = time.perf_counter()

    def floor(self, a, b):
        return a // b

    def ceil(self, a, b):
        return a // b + (a % b > 0)

    def oracle(self, ciphertext):
        self.queries += 1
        t = time.perf_counter()
        if self.queries % 500 == 0:
            print(f"Query #{self.queries} ({round(t - self.t_start, 3)} s)")

        encoded = rsa.decrypt_string(self.sk, ciphertext)

        if len(encoded) > self.k:
            raise Exception("Invalid PKCS1 encoding after decryption!")

        if len(encoded) < self.k:
            zero_pad = b"\x00" * (self.k - len(encoded))
            encoded = zero_pad + encoded

        return encoded[0:2] == b"\x00\x02"

    def encrypt(self, message_encoded):
        return rsa.encrypt_string(self.pk, message_encoded)

    def decrypt(self, ciphertext):
        return rsa.decrypt_string(self.sk, ciphertext)


if __name__ == "__main__":
    # Original message to encrypt
    message = b"Hello, RSA!"

    # Initialize RSA oracle with 256-bit key (k = 256/8 = 32 bytes)
    oracle = RSAOracle(modulus_size=256)
    k = oracle.k  # Number of bytes in the modulus

    # Create PKCS#1 encoder
    pkcs1 = PKCS1(total_bytes=k)

    # Encode the message with PKCS#1 v1.5
    padded_message = pkcs1.encode(message)
    print(f"Padded Message (hex): {padded_message.hex()}")

    # Encrypt the padded message using RSA public key
    ciphertext = oracle.encrypt(padded_message)
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # Use oracle to check if ciphertext is PKCS#1 compliant after decryption
    is_valid = oracle.oracle(ciphertext)
    print(f"Oracle PKCS#1 Compliance Check: {is_valid}")

    # Decrypt ciphertext using private key
    decrypted_padded = oracle.decrypt(ciphertext)
    print(f"Decrypted Padded Message (hex): {decrypted_padded.hex()}")

    # Decode the message from PKCS#1 format
    original_message = pkcs1.decode(decrypted_padded)
    print(f"Decoded Message: {original_message.decode()}")

