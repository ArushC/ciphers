from transposition.ngramTransposition import encrypt_vertical, decrypt_vertical
from miscellaneous import pyperclip
from cryptanalysis import ngramFrequencyAnalysis
from transposition import reverseEveryN

def main():

    message = input("Enter message: ")
    key = int(input("Enter key: "))
    remove_spaces = input("Remove spaces <y/n>?: ")
    if remove_spaces.upper() == 'Y':
        message = ''.join(message.split())
    #explanation of reversed_blocks:
    #ex. if the length of the message is 10
    #and it is encrypted using a key of 2
    #then after encryption, every block of 5 letters in the message will be reversed
    reversed_blocks = input("Reversed blocks <y/n>?: ")
    rb = True if reversed_blocks.upper() == 'Y' else False
    mode = input("Mode? <encrypt/decrypt>: ")
    if mode.upper() == 'ENCRYPT':
        filler = input("Filler = ")
        plaintext = encrypt(key, message, filler=filler, reversed_blocks=rb)
    elif mode.upper() == 'DECRYPT':
        plaintext = decrypt(key, message, reversed_blocks=rb)
    else:
        plaintext = "ERROR: Invalid mode"
    # Print with a | ("pipe" character) after it in case
    # there are spaces at the end of the decrypted message.
    print(plaintext + '|')
    print()
    print("Result copied to clipboard")
    pyperclip.copy(plaintext)

#basic route cipher -- write horizontally read down the columns
#the key specifies the width of the grid
def encrypt(key, message, filler='X', reversed_blocks=False):
    perm = tuple(range(1, (key + 1)))
    if reversed_blocks:
        return reverseEveryN.encrypt(encrypt_vertical(message, perm, n=1, filler=filler), int(len(message)/key))
    else:
        return encrypt_vertical(message, perm, n=1, filler=filler)

def decrypt(key, message, reversed_blocks=False):
    if reversed_blocks:
        message = reverseEveryN.decrypt(message, int(len(message)/key))
    permutation = tuple(range(1, int(key + 1)))
    return decrypt_vertical(message, permutation, n=1)


if __name__ == '__main__':
    main()
