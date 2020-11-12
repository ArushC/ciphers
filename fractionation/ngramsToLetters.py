from cryptanalysis import ngramFrequencyAnalysis

#89 character default alphabet --> consists of every useful character on the keyboard
DEFAULT_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+=-[]{}:;,.<>/?\|'

def ngrams_to_letters(msg, n, alphabet = DEFAULT_ALPHABET):
    ngram_list = []
    possible_ngrams = ngramFrequencyAnalysis.get_distinct_ngrams(msg, n)
    for index in range(0, len(msg), n):
        ngram_list.append(msg[index: index + n])

    result = []
    for ngram in ngram_list:
        if len(ngram) != n:
            break
        i = possible_ngrams.index(ngram)
        result.append(alphabet[i])

    return ''.join(result)


def main():

    message = input("Enter a message: ")

    message = ''.join(message.split())
    n = int(input("n = "))
    custom_alphabet = input("Custom alphabet <y/n>?: ")

    #input validation
    while not custom_alphabet.upper() in 'YN':
        custom_alphabet = input("Custom alphabet <y/n>?: ")

    alphabet = ''.join(ngramFrequencyAnalysis.get_distinct_ngrams(input("Enter an alphabet: "), n=1))  \
    if custom_alphabet.upper() == 'Y' else DEFAULT_ALPHABET

    print() #padding

    print(ngrams_to_letters(message, n, alphabet))


if __name__ == '__main__':
    main()
