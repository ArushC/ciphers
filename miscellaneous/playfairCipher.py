import math, re
from substitution.substitutionCipher import generate_keyed_alphabet

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#playfair is a digraph substitution cipher

def encrypt(msg, alphabet, omitted_letter="J", padding='X'):

    alphabet = alphabet.replace(omitted_letter, '')

    res = []

    i = 0

    while i < len(msg):

        l1 = msg[i]
        l2 = msg[i+1] if i + 1 < len(msg) else padding
        row1 = math.floor((alphabet.find(l1)) / 5)
        column1 = alphabet.find(l1) % 5

        if (l1 == l2): #same letter, add padding
            l2 = padding
            i -= 1

        row2 = math.floor((alphabet.find(l2)) / 5)
        column2 = alphabet.find(l2) % 5
                                                                                                    #   0 1 2 3 4
        if row1 == row2: #same row, shift right                                                     # 0
            l1_new = alphabet[row1 * 5 + (column1 + 1) % 5]                                         # 1
            l2_new = alphabet[row2 * 5 + (column2 + 1) % 5]                                         # 2
                                                                                                    # 3
        elif column1 == column2: #same column, shift down                                           # 4
            l1_new = alphabet[((row1 + 1) % 5) * 5 + column1]
            l2_new = alphabet[((row2 + 1) % 5) * 5 + column2]

        else: #box shift
            col_difference = column2 - column1
            l1_new = alphabet[row1 * 5 + (column1 + col_difference) % 5]
            l2_new = alphabet[row2 * 5 + (column2 - col_difference) % 5]

        res.append(l1_new)
        res.append(l2_new)
        i += 2

    return ''.join(res)


#decrypts a Playfair cipher using the standard algorithm
def decrypt(msg, alphabet, omitted_letter="J"):

    alphabet = alphabet.replace(omitted_letter, '')

    res = []

    i = 0

    while i < len(msg):

        l1 = msg[i]
        l2 = msg[i+1]
        if l1 == l2:
            print("ERROR in decryption: repeating letter sequence detected: '" + l1 + l2 + "'")
            return ''

        row1 = math.floor((alphabet.find(l1)) / 5)
        column1 = alphabet.find(l1) % 5

        row2 = math.floor((alphabet.find(l2)) / 5)
        column2 = alphabet.find(l2) % 5

        if row1 == row2: #same row, shift left (backwards from right)
            l1_new = alphabet[row1 * 5 + (column1 - 1) % 5]
            l2_new = alphabet[row2 * 5 + (column2 - 1) % 5]

        elif column1 == column2: #same column, shift up (backward from down)
            l1_new = alphabet[((row1 - 1) % 5) * 5 + column1]
            l2_new = alphabet[((row2 - 1) % 5) * 5 + column2]

        else: #box shift (standard)
            col_difference = column2 - column1
            l1_new = alphabet[row1 * 5 + (column1 + col_difference) % 5]
            l2_new = alphabet[row2 * 5 + (column2 - col_difference) % 5]

        res.append(l1_new)
        res.append(l2_new)
        i += 2

    return ''.join(res)

def main():

    msg = input("Enter a message: ")
    nonletters = re.compile('[^A-Za-z]')
    mode = input("Encrypt/decrypt <e/d>?: ")
    while not (mode.upper() in 'ED'): #input validation
        mode = input("Encrypt/decrypt <e/d>?: ")

    keyword = input("Keyword = ")
    keyword = re.sub(nonletters, '', keyword).upper()

    ommitted_letter = input("Ommitted letter = ").upper()
    while not ommitted_letter in ALPHABET and len(ommitted_letter) == 1: #more input validation
        ommitted_letter = input("Ommitted letter = ").upper()

    if mode.upper() == 'E':
        print(encrypt(msg, generate_keyed_alphabet(keyword), ommitted_letter))
    else:
        print(decrypt(msg, generate_keyed_alphabet(keyword), ommitted_letter))

if __name__ == '__main__':
    main()
