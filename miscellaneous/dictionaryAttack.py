from substitution import substitutionCipher
from substitution.affineCipher import gcd
from englishDetection import ngramScore
from substitution.manualSubDecoder import color
from englishDetection.englishScore import FULL_DICTIONARY
from transposition import ngramTransposition, redefence
from polyalphabetic import vigenereCipher
import re, time, os.path, math, numpy as np
from miscellaneous import playfairCipher, hillCipher

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

# break a cipher using a dictionary attack (40000 English words)
#works for keyword ciphers and vigenere ciphers (cipher_type = 'k' --> keyword cipher, 'v' ---> vigenere cipher,
#                                                'c' ---> columnar transposition, 'h' --> horizontal transposition,
#                                                'r' ---> redefence cipher)
def dict_attack(c, cipher_type, min_word_length=1, max_word_length = 1000, dictionary_file= FULL_DICTIONARY,
                fitness_file=ngramScore.TRIGRAMS, fitness = None):

    nonletters = re.compile('[^A-Za-z]')

    if fitness is None: #if no alternate scoring method specified, use ngram-scoring from the appropriate fitness file
        fitness = lambda x: ngramScore.ngram_score(fitness_file).score(x)

    with open(dictionary_file) as wordbook:
        # take out words from the dictionary that are > the minimum word length
        english_words = [word.strip().upper() for word in wordbook if len(word.strip()) >= min_word_length and
                         len(word.strip()) <= max_word_length]

    #if it is a Playfair cipher, ask for the ommitted letter
    if cipher_type == 'p':
        ommitted_letter = input("Ommitted letter = ")
        while not ommitted_letter in ALPHABET and len(ommitted_letter) == 1:  # more input validation
            ommitted_letter = input("Ommitted letter = ").upper()

    #if it is a Hill cipher, ask whether the keyword is written left to right or top to bottom
    if cipher_type == 'l':
        mode = input("Keyword written across rows, or down columns? <r/c>?: ").upper()
        while not mode in 'RC':
            mode = input("Please enter either 'R' for rows or 'C' for columns: ")

    scores_list = []

    for word in english_words:

        word = re.sub(nonletters, '', word).upper()

        if cipher_type == 'k':

            decryption_key = substitutionCipher.generate_keyed_alphabet(word)
            c = c.upper() #substitutionCipher program is case sensitive, so need to standardize the case
            plaintext = substitutionCipher.decrypt(c, decryption_key)

        elif cipher_type == 'p':

            decryption_key = substitutionCipher.generate_keyed_alphabet(word)
            c = c.upper()
            plaintext = playfairCipher.decrypt(c, decryption_key, ommitted_letter)

        elif cipher_type == 'l':

            decryption_key = word
            if int(math.sqrt(len(word)) + 0.5) ** 2 == len(word):
                matrix = hillCipher.get_keyword_matrix(word, mode=mode)
                if gcd(round(np.linalg.det(matrix) % 26), 26) == 1:
                    plaintext = hillCipher.decrypt(c, matrix)
                else:
                    continue
            else:
                continue

        elif cipher_type == 'v':
            decryption_key = word
            plaintext = vigenereCipher.decrypt(word, c)

        elif cipher_type == 'h':
            decryption_key = word
            plaintext = ngramTransposition.decrypt_horizontal(c, word)

        elif cipher_type == 'c':
            decryption_key = word
            plaintext = ngramTransposition.decrypt_vertical(c, word)

        else: #redefence (only tries w/ offset = 0, otherwise there are too many possible cases)

            decryption_key = word
            permutation = ngramTransposition.key_permutation(word)
            plaintext = redefence.decrypt(c, permutation)

        score = fitness(plaintext)
        scores_list.append((score, decryption_key, plaintext))

    scores_list.sort(key=lambda x: x[0], reverse=True)
    return scores_list[:10]


def print_best_solutions(scores_list):
    print()
    print(color.RED + color.BOLD + "BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%10s %15s %54s" + color.END) % ("Score:", "Key:", "Message:"))
    for i in range(10):
        try:
            print("%-5d %-15.0f %-50s %-10s" % (
                i + 1, scores_list[i][0], str(scores_list[i][1]), scores_list[i][2]))
        except IndexError:
            break


def main(message, dictionary_file=FULL_DICTIONARY, fitness_file=ngramScore.TRIGRAMS):

    cipher_type = input("""
K) Keyword cipher                        
V) Vigenere cipher
H) Horizontal transposition                        
C) Columnar transposition
R) Redefence cipher
P) Playfair cipher
L) Hill cipher
""")

    while not (cipher_type.upper() in 'KVHCRPL'):
        cipher_type = input("Please choose the type of cipher to dictionary "
                            "attack by inputting 'K', 'V', 'H', 'C', 'R', 'P', or 'L': ")

    min_word_length = input("Minimum Word Length: ")
    while not (min_word_length.isnumeric() and int(min_word_length) > 0):
        min_word_length = input("Please enter a valid minimum word length: ")

    max_word_length = input("Maximum Word Length: ")
    while not (max_word_length.isnumeric() and int(max_word_length) >= int(min_word_length)):
        max_word_length = input("Please enter a valid maximum word length: ")

    start = time.time()

    scores_list = dict_attack(message, cipher_type.lower(), int(min_word_length), int(max_word_length),
                              dictionary_file=dictionary_file, fitness_file=fitness_file)

    end = time.time() - start

    print_best_solutions(scores_list)
    print()
    print("Time: " + str(end) + " seconds")



if __name__ == '__main__':
    message = input("Enter a message: ")
    main(message) #optional: change the default dictionary file and fitness file
