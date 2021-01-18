import math, re
from substitution.substitutionCipher import generate_keyed_alphabet

DEFAULT_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#note: polybius square = coordinate cipher
#encrypts using the coordinate cipher (A --> 11, B --> 12, ..., F --> 21, ..., Z --> 55)
def encrypt(msg, alphabet=DEFAULT_ALPHABET, omitted_letter="J"):

        alphabet = alphabet.replace(omitted_letter, '')
        res = []
        for letter in msg:
            row = math.ceil((alphabet.find(letter) + 1)/5)
            column = (alphabet.find(letter) + 1) % 5 if not ((alphabet.find(letter) + 1) % 5 == 0) else 5
            res.append(row)
            res.append(column)

        return ''.join(list(map(str, res)))

#decrypts the coordinate cipher given the alphabet used
def decrypt(c, alphabet=DEFAULT_ALPHABET, omitted_letter="J"):
    alphabet = alphabet.replace(omitted_letter, '')
    res = []
    for i in range(0, len(c) - 1, 2):
        row = int(c[i])
        column = int(c[i+1])
        res.append(alphabet[5 * (row - 1) + (column - 1)])

    return ''.join(res)



def main():

    msg = input("Enter a message: ")
    nonletters = re.compile('[^A-Za-z]')
    non_one_to_five = re.compile('[^0-9]')
    mode = input("Encrypt/decrypt <e/d>?: ")
    while not (mode.upper() in 'ED'): #input validation
        mode = input("Encrypt/decrypt <e/d>?: ")

    keyword = input("Keyword = ")
    keyword = re.sub(nonletters, '', keyword).upper()

    ommitted_letter = input("Ommitted letter = ").upper()
    while not ommitted_letter in DEFAULT_ALPHABET: #more input validation
        ommitted_letter = input("Ommitted letter = ").upper()

    if mode.upper() == 'E':
        msg = re.sub(nonletters, '', msg).upper()
        print(encrypt(msg, generate_keyed_alphabet(keyword), ommitted_letter))
    else:
        msg = re.sub(non_one_to_five, '', msg).upper()
        print(decrypt(msg, generate_keyed_alphabet(keyword), ommitted_letter))


if __name__ == '__main__':
    main()
