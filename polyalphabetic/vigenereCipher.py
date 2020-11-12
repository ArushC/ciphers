from substitution import caesarCipher
import re

#VIGENERE CIPHER BY DEFINIION ONLY USES [A-Z] alphabet
#no custom alphabet possibilities (though it could potentially be implemented...)
nonletters = re.compile('[^a-zA-Z]')

def encrypt(key, message):

    result = []
    i = 0

    for letter in message:
        if not letter.isalpha(): #letter must be in A-Za-z
            result.append(letter)
            continue
        elif letter == letter.upper(): #if uppercase
            result.append(caesarCipher.encrypt(key[i % len(key)].upper(), letter)) #encode using uppercase alphabet

        else: #otherwise if lowercase, encode using lowercase alphabet
            result.append(caesarCipher.encrypt(key[i % len(key)].lower(), letter, alphabet='abcdefghijklmnopqrstuvwxyz'))

        i += 1

    return ''.join(result)


def decrypt(key, message):
    result = []
    i = 0
    for letter in message:
        if not letter.isalpha():
            result.append(letter)
            continue
        elif letter == letter.upper():  # if uppercase
            result.append(caesarCipher.decrypt(key[i % len(key)].upper(), letter))  # encode using uppercase alphabet

        else:  # otherwise if lowercase, encode using lowercase alphabet
            result.append(caesarCipher.decrypt(key[i % len(key)].lower(), letter, alphabet='abcdefghijklmnopqrstuvwxyz'))

        i += 1

    return ''.join(result)


def main():
    #This Vigenere cipher program does not allow use of a custom alphabet
    #only [A-Za-z] will be encrypted, rest will remain the same
    msg = input("Enter a message: ")
    punc = input("Maintain punctuation <y/n>?: ")

    if punc.upper() == 'N': #if not maintaining punctation convert to uppercase and strip spaces
       msg = re.sub(nonletters, '', msg).upper()

    #input validation
    while not punc.upper() in 'YN':
        punc = input("Maintain punctuation <y/n>?: ")

    key = input("Enter a key: ")

    mode = input("Encrypt or decrypt <e/d>?: ")
    if mode.upper() == 'E':
        print(encrypt(key, msg))
    elif mode.upper() == 'D':
        print(decrypt(key, msg))
    else:
        raise ValueError("ERROR: invalid mode")
        

if __name__ == '__main__':
    main()
