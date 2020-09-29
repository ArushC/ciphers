from substitution import substitutionCipher
from englishDetection import ngramScore
from substitution.manualSubDecoder import color
from englishDetection.englishScore import FULL_DICTIONARY
from polyalphabetic import vigenereCipher
import re

# break a cipher using a dictionary attack (40000 English words)
#works for keyword ciphers and vigenere ciphers (cipher_type = 'k' --> keyword cipher, else vigenere cipher)
def dict_attack(c, cipher_type, min_word_length=1, dictionary_file=FULL_DICTIONARY, fitness_file=ngramScore.TRIGRAMS):
    nonletters = re.compile('[^A-Za-z]')
    fitness = ngramScore.ngram_score(fitness_file)

    with open(FULL_DICTIONARY) as wordbook:
        # take out words from the dictionary that are > the minimum word length
        english_words = [word.strip().upper() for word in wordbook if len(word.strip()) >= min_word_length]

    scores_list = []

    for word in english_words:
        word = re.sub(nonletters, '', word).upper()
        if cipher_type == 'k':
            decryption_key = substitutionCipher.generate_keyed_alphabet(word)
            c = c.upper() #substitutionCipher program is case sensitive, so need to standardize the case
            plaintext = substitutionCipher.decrypt(c, decryption_key)
        else:
            decryption_key = word
            plaintext = vigenereCipher.decrypt(word, c)
        score = fitness.score(plaintext)
        scores_list.append((score, decryption_key, plaintext))

    scores_list.sort(key=lambda x: x[0], reverse=True)
    return scores_list[:10]


def print_best_solutions(scores_list):
    print()
    print(color.RED + color.BOLD + " BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%10s %15s %54s" + color.END) % ("Score:", "Key:", "Message:"))
    for i in range(10):
        try:
            print("%-5d %-15.0f %-50s %-10s" % (
                i + 1, scores_list[i][0], str(scores_list[i][1]), scores_list[i][2]))
        except IndexError:
            break


def main(message, dictionary_file=FULL_DICTIONARY, fitness_file=ngramScore.TRIGRAMS):

    cipher_type = input("Keyword cipher or Vigenere cipher <k/v>?: ")

    while not (cipher_type.upper() in 'KV'):
        cipher_type = input("Please input either 'k' for a keyword cipher or 'v' for a Vigenere cipher: ")

    scores_list = dict_attack(message, cipher_type.lower(), dictionary_file=dictionary_file, fitness_file=fitness_file)
    print_best_solutions(scores_list)


if __name__ == '__main__':
    message = input("Enter a message: ")
    main(message) #optional: change the default dictionary file and fitness file
    
    
