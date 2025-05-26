import utils  # Importing helper functions like generate_prime, modinv, etc.

# Function to generate RSA key pair (public and private keys)
def generate_key(modulus_length):
    prime_length = modulus_length // 2  # Each prime number will be half the total modulus length

    e = 3  # Public exponent. Commonly used small exponent. Vulnerable to Bleichenbacher's attack if used with improper padding.

    # Generate the first prime number `p` such that (p - 1) is not divisible by e
    p = 4
    while (p - 1) % e == 0:
        p = utils.generate_prime(prime_length)

    # Generate the second prime number `q`, which must be different from `p` and also satisfy (q - 1) % e ≠ 0
    q = p
    while q == p or (q - 1) % e == 0:
        q = utils.generate_prime(prime_length)

    n = p * q  # RSA modulus
    phi = (p - 1) * (q - 1)  # Euler’s totient function

    d = utils.modinv(e, phi)  # Private exponent: modular inverse of e modulo phi

    public_key = (n, e)   # Public key = (modulus, exponent)
    secret_key = (n, d)   # Private key = (modulus, exponent)

    return public_key, secret_key


# Function to encrypt an integer message using RSA public key
def encrypt_integer(public_key, m):
    (n, e) = public_key

    # Ensure the message is smaller than the modulus
    if m > n:
        raise ValueError("Message is too big for current RSA scheme!")

    # Perform RSA encryption: c = m^e mod n
    return pow(m, e, n)


# Function to decrypt an integer ciphertext using RSA private key
def decrypt_integer(secret_key, c):
    (n, d) = secret_key

    # Perform RSA decryption: m = c^d mod n
    return pow(c, d, n)


# Function to encrypt a string (byte message) using RSA
def encrypt_string(public_key, message):
    # Convert message from bytes to integer
    integer = utils.bytes_to_integer(message)

    # Encrypt the integer
    enc_integer = encrypt_integer(public_key, integer)

    # Convert encrypted integer back to bytes
    enc_string = utils.integer_to_bytes(enc_integer)

    return enc_string


# Function to decrypt a ciphertext (in bytes) back to the original message
def decrypt_string(secret_key, ciphertext):
    # Convert encrypted byte string to integer
    enc_integer = utils.bytes_to_integer(ciphertext)

    # Decrypt the integer
    integer = decrypt_integer(secret_key, enc_integer)

    # Convert the result back to bytes (original message)
    message = utils.integer_to_bytes(integer)

    return message
