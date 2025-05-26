import random  # For generating random numbers
import gmpy2   # For fast arithmetic operations, especially primality testing
# Extended Euclidean Algorithm
# Returns the greatest common divisor of a and b,
# and the coefficients x and y such that: a*x + b*y = gcd(a, b)
def egcd(a, b):
    if a == 0:
        return b, 0, 1

    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


# Modular Inverse: finds x such that (a * x) % m == 1
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m


# Function to generate a random prime number of given bit length
def generate_prime(bit_length):
    while True:
        # Lower and upper bounds for the random number
        lb = 2 ** (bit_length - 1)
        ub = (2 ** bit_length) - 1

        # Generate a random candidate in the range
        candidate = random.randint(lb, ub)

        # Return if it's prime (using gmpy2's probabilistic primality test)
        if gmpy2.is_prime(candidate):
            return candidate


# Converts a byte object to an integer (big-endian)
def bytes_to_integer(bytes_obj):
    return int.from_bytes(bytes_obj, byteorder="big")


# Converts an integer to a byte object (big-endian)
def integer_to_bytes(integer):
    k = integer.bit_length()

    # Calculate the required number of bytes to hold the integer
    bytes_length = k // 8 + (k % 8 > 0)

    # Convert integer to bytes
    bytes_obj = integer.to_bytes(bytes_length, byteorder="big")

    return bytes_obj
