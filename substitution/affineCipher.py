#Affine Cipher encryption and decryption functions
#default alphabet is [A-Z]
#Change alphabet below if you want to use a custom alphabet
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#encryption: C = (aP + b) % m where m = length of the alphabet
def encrypt(a, b, message, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):

    ciphertext_list = [(alphabet[(a * (alphabet.find(message[i])) + b) % len(alphabet)]
                      if alphabet.find(message[i]) != -1 else message[i])
                      for i in range(len(message))]

    return ''.join(ciphertext_list)


# decryption: (C - b) * (a^(-1) mod m) where m = length of the alphabet
def decrypt(a, b, message, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):

    ciphertext_list = [(alphabet[(((alphabet.find(message[i])) - b)
                        * inv_mod(a, len(alphabet))) % len(alphabet)]
                        if alphabet.find(message[i]) != -1 else message[i])
                       for i in range(len(message))]

    return ''.join(ciphertext_list)

#this inverse_modulo function was taken from the book "Cracking Codes with Python" by Al Sweigart
#this algorithm works for EXTREMELY large numbers (good for RSA decryption)
def inv_mod(a, m):
    # Return the modular inverse of a % m, which is
    # the number x such that a*x % m = 1

    if gcd(a, m) != 1:
        return None # No mod inverse exists if a & m aren't relatively prime.

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # Note that // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

#gcd function also came from the book "Cracking Codes with Python"
def gcd(a, b):
    # Return the Greatest Common Divisor of a and b using Euclid's Algorithm
    while a != 0:
        a, b = b % a, a
    return b

def main():
    # note: case sensitive! message should be ALL UPPERCASE
    print("WARNING: this program is case-sensitive. The default alphabet is the capital alphabet A-Z.")
    msg = input("Enter message: ")
    a = int(input("a = "))
    b = int(input("b = "))
    mode = input("Encrypt or decrypt <e/d>?: ")
    if gcd(a, len(ALPHABET)) != 1:
        raise ValueError("ERROR: 'a' is not coprime to the length of the alphabet")
    if mode.upper() == 'E':
        print(encrypt(a, b, msg, ALPHABET))
    elif mode.upper() == 'D':
        print(decrypt(a, b, msg, ALPHABET))
    else:
        raise ValueError("ERROR: invalid mode")

if __name__ == '__main__':
    main()
