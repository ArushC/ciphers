'''
Allows scoring of text using n-gram probabilities
This code was modified from http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/#a-python-implementation
use with english_monograms, english_bigrams, english_trigrams, english_quadgrams, or english_quintgrams
best with english_quadgrams
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

    def __init__(self, ngramfile ,sep=' '):
        ''' load a file containing ngrams and counts, calculate log probabilities '''
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

    def score(self,text):
        ''' compute the score of text '''
        score = 0
        ngrams = self.ngrams.__getitem__
        for i in range(len(text) - self.L+1):
            score += ngrams(text[i:i + self.L]) if text[i:i + self.L] in self.ngrams else self.floor

        return score
