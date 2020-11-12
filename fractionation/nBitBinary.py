from cryptanalysis.ngramFrequencyAnalysis import break_into_ngrams, get_distinct_ngrams

#89 character alphabet --> consists of every useful character on the keyboard
DEFAULT_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+=-[]{}:;,.<>/?\|'

def encrypt(message, n, alphabet=DEFAULT_ALPHABET):
    encrypted = []
    for char in message:
        if char in alphabet:
            index = alphabet.find(char)
            encrypted.append(bin(index)[2:].zfill(n))

    return ''.join(encrypted)


def decrypt(message, n, alphabet=DEFAULT_ALPHABET):
    decrypted = []
    parts = break_into_ngrams(message, n)
    for part in parts:
        index = int(part, 2)
        decrypted.append(alphabet[index])

    return ''.join(decrypted)


def main():

    msg = input("Enter a message: ")
    # IMPORTANT PRECONDITION: ENTIRE MESSAGE SHOULD BE UPPERCASE
    msg = ''.join(msg.split()) #case matters! only spaces are removed
    n = int(input("n = "))
    custom_alphabet = input("Custom alphabet <y/n>?: ")

    # input validation
    while not custom_alphabet.upper() in 'YN':
        custom_alphabet = input("Custom alphabet <y/n>?: ")

    alphabet = ''.join(get_distinct_ngrams(input("Enter an alphabet: "), n=1)) \
        if custom_alphabet.upper() == 'Y' else DEFAULT_ALPHABET

    mode = input("Mode <encrypt/decrypt>?: ")

    #input validation
    while not (mode.upper() == 'ENCRYPT' or mode.upper() == 'DECRYPT'):
        mode = input("<encrypt/decrypt>?: ")

    print() #padding

    print(encrypt(msg, n, alphabet)) if mode.upper() == 'ENCRYPT' \
        else print(decrypt(msg, n, alphabet))

    
if __name__ == '__main__':
    main()  
