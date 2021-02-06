from englishDetection.trie import Trie
from cryptanalysis.chiSquaredTest import calculate_chi_squared
import re
import os.path

MY_PATH = os.path.abspath(os.path.dirname(__file__))

MIN_WORD_LENGTH = 3
COMMON_WORDS = os.path.join(MY_PATH, '../englishDetection/commonEnglishWords.txt')
FULL_DICTIONARY = os.path.join(MY_PATH, '../englishDetection/dictionary.txt')
WORD_LOOKUP = os.path.join(MY_PATH, '../englishDetection/wordLookup.txt')
#for homophonic substitution cipher (and fast substitution cipher) --> quick access to bigram frequencies file
BIGRAM_FREQUENCIES = os.path.join(MY_PATH, '../englishDetection/english_bigram_frequencies.txt')

#use this scoring method for transposition ciphers
def english_word_score(msg : str, filename=COMMON_WORDS, min_word_length=MIN_WORD_LENGTH): #calculates the number of common english words present in the message

    with open(filename) as wordbook:
        # take out words from the dictionary that are < the minimum word length
        english_words = [word.strip().upper() for word in wordbook if len(word.strip()) >= min_word_length]  # set

    message = msg.upper()
    trie = Trie()
    for word in english_words:
        trie.add(word)
    return len(re.findall(trie.pattern(), message))

#use this scoring method for every other type of cipher (higher score is better)
#returns 1 over the words score divided by chi-squared
#note: this scoring method is relatively slow, ngram logarithmic scores have been found to work much better
def english_word_and_frequencies_score(msg : str, filename=COMMON_WORDS, min_word_length=MIN_WORD_LENGTH):
    return english_word_score(msg, filename, min_word_length)/calculate_chi_squared(msg)


def main():

    cipher = input("Enter a message: ")
    min_word_length = int(input("Minimum word length = "))
    print("English word score (from common English words): " +
          str(english_word_score(cipher, min_word_length=min_word_length)))
    print("English word and frequencies score (from common English words): %.2f"
          %english_word_and_frequencies_score(cipher, min_word_length=min_word_length))


if __name__ == '__main__':
    main()
