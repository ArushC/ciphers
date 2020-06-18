#Caesar Shift Cipher encryption and decryption functions
#default alphabet is [A-Z]
#Change alphabet below if you want to use a custom alphabet
from cryptanalysis.ngramFrequencyAnalysis import get_distinct_ngrams
DEFAULT_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#note that key can be either a letter in the alphabet or a numerical value
def encrypt(key, message, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):

    if str(key) in alphabet: #custom alphabet should NOT contain 0-9 or this will not work correctly
        key = alphabet.find(key) #shift = index of letter in the alphabet
    else:
        key = int(key)

    ciphertext_list = [(alphabet[(alphabet.find(message[i]) + key) % len(alphabet)]
                      if alphabet.find(message[i]) != -1 else message[i])
                      for i in range(len(message))]

    return ''.join(ciphertext_list)


def decrypt(key, message, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):

    if str(key) in alphabet:  # custom alphabet should NOT contain 0-9 or this will not work correctly
        key = alphabet.find(key)  # shift = index of letter in the alphabet
    else:
        key = int(key)

    ciphertext_list = [
        (alphabet[(alphabet.find(message[i]) - key) % len(alphabet)]
         if alphabet.find(message[i]) != -1 else message[i])
        for i in range(len(message))]

    return ''.join(ciphertext_list)


def main():
    #PRECONDITION: message-case matches ALPHABET case (this is case-sensitive!)
    msg = input("Enter message: ")
    custom_alphabet = input("Custom alphabet <y/n>?: ")

    # input validation
    while not custom_alphabet.upper() in 'YN':
        custom_alphabet = input("Custom alphabet <y/n>?: ")

    alphabet = ''.join(get_distinct_ngrams(input("Enter an alphabet: "), n=1)) \
        if custom_alphabet.upper() == 'Y' else DEFAULT_ALPHABET


    key = input("Enter shift: ")

    mode = input("Encrypt or decrypt <e/d>?: ")
    if mode.upper() == 'E':
        print(encrypt(key, msg, alphabet))
    elif mode.upper() == 'D':
        print(decrypt(key, msg, alphabet))
    else:
        raise ValueError("ERROR: invalid mode")

if __name__ == '__main__':
   main()



















