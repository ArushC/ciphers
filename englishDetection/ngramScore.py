'''
Allows scoring of text using n-gram probabilities
The ngram_score class was borrowed from http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/#a-python-implementation
It was originally written by James Lyons and has been modified slightly for better readability
The english_monograms, english_bigrams, english_trigrams, english_quadgrams, and english_quintgrams txt files were also sourced from this site
'''
import os.path
from math import log10

MY_PATH = os.path.abspath(os.path.dirname(__file__))

#ADD FILENAMES HERE -- these can be imported to other files
MONOGRAMS = os.path.join(MY_PATH, '../englishDetection/english_monograms.txt')
BIGRAMS = os.path.join(MY_PATH,'../englishDetection/english_bigrams.txt')
TRIGRAMS = os.path.join(MY_PATH,'../englishDetection/english_trigrams.txt')
QUADGRAMS = os.path.join(MY_PATH,'../englishDetection/english_quadgrams.txt')
QUINTGRAMS = os.path.join(MY_PATH,'../englishDetection/english_quintgrams.txt')

class ngram_score(object):

    def __init__(self, ngramfile, sep=' '):
        
        #load a file containing ngrams and counts and calculate log probabilities
        self.ngrams = {}
        for line in open(ngramfile):
            key, count = line.split(sep)
            self.ngrams[key] = int(count)
        self.L = len(key)
        self.N = sum(self.ngrams.values())
        
        #calculate log probabilities
        for key in self.ngrams.keys():
            self.ngrams[key] = log10(float(self.ngrams[key])/self.N)
        self.floor = log10(0.01 / self.N)

    def score(self, text):
        
        #compute the english score of the text based on the log probabilities 
        score = 0
        ngrams = self.ngrams.__getitem__
        for i in range(len(text) - self.L+1):
            score += ngrams(text[i:i + self.L]) if text[i:i + self.L] in self.ngrams else self.floor

        return score

def main():
    cipher = input("Enter a message: ")
    print("Monogram score: %.2f" %ngram_score(MONOGRAMS).score(cipher))
    print("Bigram score: %.2f" %ngram_score(BIGRAMS).score(cipher))
    print("Trigram score: %.2f" %ngram_score(TRIGRAMS).score(cipher))
    print("Quadgram score: %.2f" %ngram_score(QUADGRAMS).score(cipher))
    print("Quintgram score: %.2f" %ngram_score(QUINTGRAMS).score(cipher))

if __name__ == '__main__':
    main()
