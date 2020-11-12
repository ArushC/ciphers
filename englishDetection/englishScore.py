from englishDetection.trie import Trie
from cryptanalysis.chiSquaredTest import calculate_chi_squared
import re
import os.path

MY_PATH = os.path.abspath(os.path.dirname(__file__))

MIN_WORD_LENGTH = 3
COMMON_WORDS = os.path.join(MY_PATH, '../englishDetection/commonEnglishWords.txt')
FULL_DICTIONARY = os.path.join(MY_PATH, '../englishDetection/dictionary.txt')
WORD_LOOKUP = os.path.join(MY_PATH, '../englishDetection/wordLookup.txt')

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

#use this scoring method for every other type of cipher
#returns 1 over the words score divided by chi-squared
#higher score is better
def english_word_and_frequencies_score(msg : str, filename=COMMON_WORDS, min_word_length=MIN_WORD_LENGTH):
    return english_word_score(msg, filename, min_word_length)/calculate_chi_squared(msg)

