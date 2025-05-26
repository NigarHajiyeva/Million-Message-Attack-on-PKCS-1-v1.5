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


class MillionMessageAttack:
    """
    Implementation of Million Message's attack using an RSA oracle and PKCS#1.
    """

    def __init__(self, rsa_oracle: RSAOracle):
        self.oracle = rsa_oracle
        self.n = rsa_oracle.n
        self.e = rsa_oracle.e
        self.k = rsa_oracle.k
        self.pkcs1 = PKCS1(self.k)
        self.B = 2 ** (8 * (self.k - 2))  # B = 2^(8*(k-2)) as per PKCS#1 v1.5

    def floor(self, a, b):
        return a // b

    def ceil(self, a, b):
        return a // b + (a % b > 0)

    def prepare(self, message):
        """
        Encode message, encrypt with RSA PKCS#1 v1.5
        """
        message_encoded = self.pkcs1.encode(message)
        ciphertext = self.oracle.encrypt(message_encoded)
        return ciphertext

    def find_smallest_s(self, lower_bound, c):
        # Find the smallest s such that (c * s^e mod n) is PKCS conforming
        s = lower_bound
        while True:
            attempt = (c * pow(s, self.e, self.n)) % self.n
            attempt_bytes = utils.integer_to_bytes(attempt)

            if self.oracle.oracle(attempt_bytes):
                return s
            s += 1

    def find_s_in_range(self, a, b, prev_s, c):
        # Try to find s in a specific range by adjusting r values
        ri = self.ceil(2 * (b * prev_s - 2 * self.B), self.n)

        while True:
            si_lower = self.ceil(2 * self.B + ri * self.n, b)
            si_upper = self.ceil(3 * self.B + ri * self.n, a)

            for si in range(si_lower, si_upper):
                attempt = (c * pow(si, self.e, self.n)) % self.n
                attempt_bytes = utils.integer_to_bytes(attempt)

                if self.oracle.oracle(attempt_bytes):
                    return si

            ri += 1

    def safe_interval_insert(self, M_new, interval):
        # Merge overlapping intervals to avoid redundant guesses
        for i, (a, b) in enumerate(M_new):
            if (b >= interval.lower_bound) and (a <= interval.upper_bound):
                lb = min(a, interval.lower_bound)
                ub = max(b, interval.upper_bound)
                M_new[i] = Interval(lb, ub)
                return M_new
        M_new.append(interval)
        return M_new

    def update_intervals(self, M, s):
        # Update the set of intervals [a, b] containing the plaintext
        M_new = []
        for a, b in M:
            r_lower = self.ceil(a * s - 3 * self.B + 1, self.n)
            r_upper = self.ceil(b * s - 2 * self.B, self.n)

            for r in range(r_lower, r_upper):
                lower_bound = max(a, self.ceil(2 * self.B + r * self.n, s))
                upper_bound = min(b, self.floor(3 * self.B - 1 + r * self.n, s))
                interval = Interval(lower_bound, upper_bound)
                M_new = self.safe_interval_insert(M_new, interval)

        M.clear()
        return M_new

    def run(self, ciphertext):
        # Main attack loop
        c = utils.bytes_to_integer(ciphertext)
        M = [Interval(2 * self.B, 3 * self.B - 1)]  # Initial interval

        s = self.find_smallest_s(self.ceil(self.n, 3 * self.B), c)  # Step 1: find first valid s
        M = self.update_intervals(M, s)

        while True:
            if len(M) >= 2:
                # More than one interval, continue finding valid s
                s = self.find_smallest_s(s + 1, c)
            elif len(M) == 1:
                # Only one interval left, try to narrow down s more efficiently
                a, b = M[0]
                if a == b:
                    return utils.integer_to_bytes(a % self.n)  # Plaintext found
                s = self.find_s_in_range(a, b, s, c)
            M = self.update_intervals(M, s)


def main():
    rsa_oracle = RSAOracle()
    attack = MillionMessageAttack(rsa_oracle)

    message = b"m1ll10nm3ss4g34tt4ck"
    ciphertext = attack.prepare(message)
    decrypted = attack.run(ciphertext)
    decrypted = attack.pkcs1.decode(decrypted)

    assert decrypted == message  # Ensure successful decryption

    print("----------")
    print(f"Total Queries:\t{rsa_oracle.queries}")
    print(f"Original Message:\t{message}")
    print(f"Decrypted by Attack:\t{decrypted}")


if __name__ == "__main__":
    main()