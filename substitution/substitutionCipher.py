from random import shuffle
from collections import OrderedDict
from cryptanalysis.ngramFrequencyAnalysis import get_distinct_ngrams
import sys

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#precondition: alphabet is a valid alphabet
def encrypt(message, alphabet, default_alphabet=ALPHABET):
    result = [alphabet[default_alphabet.find(message[i])] if default_alphabet.find(message[i])
              != -1 else message[i]  for i in range(len(message))]
    return ''.join(result)

#precondition: alphabet is a valid alphabet
def decrypt(message, alphabet, default_alphabet=ALPHABET):
    result = [default_alphabet[alphabet.find(message[i])] if alphabet.find(message[i])
                                                             != -1 else message[i] for i in range(len(message))]
    return ''.join(result)


def generate_random_alphabet(default_alphabet=ALPHABET):
    alph_list = list(default_alphabet)
    shuffle(alph_list)
    return ''.join(alph_list)


#generates a keyed alphabet given a keyword
#ex. key = KEY
#alphabet: KEYABCDFGHIJLMNOPQRSTUVWXZ
def generate_keyed_alphabet(keyword, default_alphabet=ALPHABET):

    key_without_rep = ''.join(OrderedDict.fromkeys(keyword))
    alph_without_key = ''.join([default_alphabet[i] if default_alphabet[i] not in key_without_rep
                        else '' for i in range(len(default_alphabet))])

    return key_without_rep + alph_without_key

#inverts an alphabet (e.g. if A --> B, B --> C, C --> D, the inverse will be B --> A, C --> B, D --> C)
#precondition: alphabet is not incomplete
def invert(alphabet, default_alphabet=ALPHABET):

    res = [''] * len(alphabet)

    count = 0
    for letter in alphabet:
        res[default_alphabet.find(letter)] = default_alphabet[count]
        count += 1

    return ''.join(res)

if __name__ == '__main__':
    #note: case sensitive! case matters -- message should be all uppercase
    msg = input("Enter a message: ")

    custom_def_alphabet = input("Custom (default) alphabet <y/n>?: ")

    # input validation
    while not custom_def_alphabet.upper() in 'YN':
        custom_def_alphabet = input("Custom alphabet <y/n>?: ")

    custom_def_alphabet = ''.join(get_distinct_ngrams(input("Enter a custom (default) alphabet: "), n=1)) \
        if custom_def_alphabet.upper() == 'Y' else ALPHABET

    mode = input("Encrypt/Decrypt <e/d>?: ")
    # more input validation :-)
    while not mode.upper() in 'ED':
        key = input("Please enter a valid mode:")
    if mode.upper() == 'E':
        r = input("Encrypt with a randomly generated alphabet <y/n>?: ")
        while not r.upper() in 'YN':
            key = input("Please enter 'y' or 'n':")
        if r.upper() == 'Y':
            random_alph = generate_random_alphabet(custom_def_alphabet)
            print(encrypt(msg, random_alph, custom_def_alphabet))
            print("Alphabet Used: " + random_alph)
            sys.exit(0)
        else:
            key = input("Enter key: ")
            # input validation
            while not len(key) <= len(custom_def_alphabet):
                key = input("Please enter a valid key: ")

            keyed_alphabet = generate_keyed_alphabet(key, custom_def_alphabet)

            print(encrypt(msg, keyed_alphabet, custom_def_alphabet))

    else:
        key = input("Enter key: ")
        # input validation
        while not len(key) <= len(custom_def_alphabet):
            key = input("Please enter a valid key: ")

        keyed_alphabet = generate_keyed_alphabet(key, custom_def_alphabet)
        print(decrypt(msg, keyed_alphabet, custom_def_alphabet))

        
