from math import gcd
from transposition.ngramTransposition import invert

#This cipher is described in more detail at https://www.dcode.fr/skip-cipher

def encrypt_skip(msg, skip, start_index=0):

    # skip must be coprime to message length
    if gcd(len(msg), skip) != 1:
        print("ERROR: message length is not comprime to skip size.")
        return ''

    else:
        index = start_index
        ciphertext = []
        while index < start_index + len(msg) * skip:
            ciphertext.append(msg[index % len(msg)])
            index += skip

        return ''.join(ciphertext)

#encrypts a list of indexes (used for decryption)
def encrypt_indexes_skip(indexes_list, skip, start_index=0):

    if gcd(len(indexes_list), skip) != 1:
        print("ERROR: message length is not comprime to skip size.")
        return ''

    else:
        index = start_index
        rearranged_indexes = []
        while index < start_index + len(indexes_list) * skip:
            rearranged_indexes.append(indexes_list[index % len(indexes_list)])
            index += skip

        return rearranged_indexes


def decrypt_skip(msg, skip, start_index=0):

    if gcd(len(msg), skip) != 1:
        print("ERROR: message length is not comprime to skip size.")
        return ''

    indexes = list(range(0, len(msg)))
    rearranged = invert(encrypt_indexes_skip(indexes, skip, start_index))
    plaintext = [msg[index] for index in rearranged]
    return ''.join(plaintext)


def main():
    message = input("Enter a message: ")
    remove = input("Remove spaces <y/n>?: ")
    if remove.upper() == 'Y':
        message = ''.join(message.split())
    mode = input("Encrypt or decrypt <e/d>?: ")
    start_index = int(input("Start index = "))
    skip = int(input("Skip = "))
    res = encrypt_skip(message, skip, start_index) if mode.upper() == 'E' else decrypt_skip(message, skip, start_index)
    
    # Print with a | ("pipe" character) after it in case
    # there are spaces at the end of the decrypted message.
    print(res +  "|")
    pyperclip.copy(res)
    print("<Copied to clipboard>")
    print("Warning: do not copy this manually because there is a pipe character at the end of the message that"
          " will mess up decryption.")


if __name__ == '__main__':
    main()
