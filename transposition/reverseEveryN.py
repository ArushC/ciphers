from cryptanalysis.ngramFrequencyAnalysis import break_into_ngrams, break_into_ngrams_with_remainders

def reverse(message): #reverses the entire message
    translated = ""
    for i in range(len(message) - 1, -1, -1):
        translated += message[i]
    return translated #return the reversed message

#reverses every n characters in a message
#precondition: key is an integer value such that 0 < key < len(message)
def encrypt(message, key, splitter=''):

    ngrams = break_into_ngrams_with_remainders(message, key)
    are_remainders = int(len(message)/key) != len(message)/key
    if not are_remainders:
        stop = len(ngrams)
        extra = ''
    else:
        stop = len(ngrams) - 1
        extra = reverse(ngrams[len(ngrams) - 1])

    result = [reverse(ngrams[i]) for i in range(stop)]
    return ''.join(result) + splitter + extra


def decrypt(message, key, splitter=''):
    message = message.replace(splitter, '') #splitter is not a part of the actual message
    num_of_remainders = len(message) % key
    truncated = message[:len(message) - num_of_remainders]
    remainder = message[len(message) - num_of_remainders:]
    return encrypt(truncated, key) + reverse(remainder)


def main():
    message = input("Enter message: ")
    key = int(input("Enter key: "))
    mode = input("Encrypt/Decrypt <e/d>?: ")
    if mode.upper() == 'E':
        res = encrypt(message, key)
    elif mode.upper() == 'D':
        res = decrypt(message, key)

    # Print with a | ("pipe" character) after it in case
    # there are spaces at the end of the decrypted message.
    print(res + "|")
    pyperclip.copy(res)
    print("<Copied to clipboard>")


if __name__ == '__main__':
     main()
