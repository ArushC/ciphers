from substitution import substitutionCipher
from englishDetection import ngramScore
from substitution.manualSubDecoder import color
from englishDetection.englishScore import FULL_DICTIONARY
from transposition import ngramTransposition, redefence
from polyalphabetic import vigenereCipher
import re

# break a cipher using a dictionary attack (40000 English words)
#works for keyword ciphers and vigenere ciphers (cipher_type = 'k' --> keyword cipher, 'v' ---> vigenere cipher,
#                                                'c' ---> columnar transposition, 'h' --> horizontal transposition,
#                                                'r' ---> redefence cipher)
def dict_attack(c, cipher_type, min_word_length=1, max_word_length = 1000, dictionary_file= FULL_DICTIONARY,
                fitness_file=ngramScore.TRIGRAMS, fitness = None):

    nonletters = re.compile('[^A-Za-z]')

    if fitness is None: #if no alternate scoring method specified, use ngram-scoring from the appropriate fitness file
        fitness = lambda x: ngramScore.ngram_score(fitness_file).score(x)

    with open(FULL_DICTIONARY) as wordbook:
        # take out words from the dictionary that are > the minimum word length
        english_words = [word.strip().upper() for word in wordbook if len(word.strip()) >= min_word_length and
                         len(word.strip()) <= max_word_length]

    scores_list = []

    for word in english_words:
        word = re.sub(nonletters, '', word).upper()
        if cipher_type == 'k':
            decryption_key = substitutionCipher.generate_keyed_alphabet(word)
            c = c.upper() #substitutionCipher program is case sensitive, so need to standardize the case
            plaintext = substitutionCipher.decrypt(c, decryption_key)
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
""")

    while not (cipher_type.upper() in 'KVHCR'):
        cipher_type = input("Please choose the type of cipher to dictionary "
                            "attack by inputting 'K', 'V', 'H', 'C', or 'R': ")

    min_word_length = input("Minimum Word Length: ")
    while not (min_word_length.isnumeric() and int(min_word_length) > 0):
        min_word_length = input("Please enter a valid minimum word length:")

    max_word_length = input("Maximum Word Length: ")
    while not (max_word_length.isnumeric() and int(max_word_length) >= int(min_word_length)):
        max_word_length = input("Please enter a valid maximum word length:")

    scores_list = dict_attack(message, cipher_type.lower(), int(min_word_length), int(max_word_length),
                              dictionary_file=dictionary_file, fitness_file=fitness_file)

    print_best_solutions(scores_list)


if __name__ == '__main__':
    message = input("Enter a message: ")
    main(message) #optional: change the default dictionary file and fitness file
