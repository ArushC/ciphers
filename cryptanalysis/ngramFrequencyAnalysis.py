import operator
import re

#This code works for both block windows and sliding windows
#each function has a boolean parameter 'sliding' to indicate whether the message
#should be analyzed in fixed blocks or in a sliding window
#depending on what you want to analyze (comment/uncomment the appropriate line):
#[A-Z] ONLY (default)
alph = '[^A-Za-z]'
#[0-9] ONLY
#alph = '[^0-9]'
#[A-Z] with spaces
#alph = '[^A-Za-z\s]'
#[0-9] with spaces
#alph = '[^0-9\s]'
#[A-Z] & [0-9]
#alph ='[^A-Za-z0-9]'
#[A-Z] & [0-9] with spaces
#alph ='[^A-Za-z0-9\s]'
#ALL CHARACTERS (including punctuation/symbols)
#alph = '[\n]' #newline does not count as a character
pattern = re.compile(alph)

#returns a list that contains all of the different types of n_grams that appear in the ciphertext
def get_distinct_ngrams(C, n, sliding=False):
    n_gram_list = []
    step = 1 if sliding else n
    for index in range(0, len(C), step):
        part = C[index: index + n]
        if len(part) != n:
            continue
        if not part in n_gram_list:
            n_gram_list.append(part)
    return n_gram_list

##
#returns a list that contains all the n-grams in the message (truncating remainders)
def break_into_ngrams(C, n, sliding=False):
    n_gram_list = []
    step = 1 if sliding else n
    for index in range(0, len(C), step):
        part = C[index: index + n]
        if len(part) == n:
            n_gram_list.append(part)

    return n_gram_list

#this function ONLY applies for a block-window
def break_into_ngrams_with_remainders(C, n):
    n_gram_list = []
    step = n
    for index in range(0, len(C), step):
        try:
            part = C[index: index + n]
            n_gram_list.append(part)
        except IndexError:
            #if index error, simply append all remaining characters as a separate 'remainders' entry
            n_gram_list.append(C[index:len(C) - 1])


    return n_gram_list

#returns the number of different types of n_grams in the ciphertext
def count_distinct_ngrams(C, n, sliding=False):
    return len(get_distinct_ngrams(C, n, sliding))

#returns a dictionary of n_grams sorted by frequency of appearances of each n-gram
def get_ngrams_with_frequencies(C, n, sliding=False):
    n_gram_counter = dict()
    step = 1 if sliding else n
    for index in range(0, len(C), step):
        part = C[index: index + n]
        if len(part) != n:
            continue
        elif not part in n_gram_counter.keys():
            n_gram_counter[part] = 1
        else:
            n_gram_counter[part] += 1

    sorted_n_gram_counter = dict(sorted(n_gram_counter.items(), key=operator.itemgetter(1), reverse=True))
    return sorted_n_gram_counter


def get_most_frequent_ngram_count(C, n, sliding=False):
    d = get_ngrams_with_frequencies(C, n, sliding)
    return list(d.values())[0]

def get_most_frequent_ngram(C, n, sliding=False):
    d = get_ngrams_with_frequencies(C, n, sliding)
    return list(d.keys())[0]

#replace every occurence of old with new in the message --> works in a block window
#ex. C = 'ADAD', old = 'DA', returns 'ADAD' because 'DA' is not a 2-gram in the block window
def replace_every_occurence_of(C, old, new):
    parts = break_into_ngrams(C, len(old))
    for i in range(len(parts)):
        if parts[i] == old:
            parts[i] = new
    return ''.join(parts)

#prints bigram followed by # of appearances followed by percentage occurence (follows DCode's format)
def print_analysis(C, n, sliding=False):
    total = sum_of_appearances(C, n, sliding)
    for key, val in get_ngrams_with_frequencies(C, n, sliding).items():
        print(key + ": " + str(val) + " ", end='')
        frequency = val/total
        print("%.2f%%" %(frequency * 100))

    print("#n: %d" %count_distinct_ngrams(C, n, sliding))
    print("Total appearances: %d" %sum_of_appearances(C, n, sliding))
    print()

#returns the total number of n-grams that appeared in the text
def sum_of_appearances(C, n, sliding=False):
    d = get_ngrams_with_frequencies(C, n, sliding)
    sum = 0
    for num in d.values():
        sum += num
    return sum


if __name__ == '__main__':
    inp = input("Enter a message:")
    filtered = pattern.sub('' , inp)
    case_sensitive = input("Case sensitive ('A' != 'a')? <y/n>: ")
    #input validation loop
    while not (case_sensitive.upper() == 'Y' or case_sensitive.upper() == 'N'):
        case_sensitive = input("Case sensitive ('A' != 'a')? <y/n>: ")
    #if not case sensitive
    if case_sensitive.upper() == 'N':
        #make the entire message uppercase
        filtered = filtered.upper()

    n = int(input("N-grams? n = "))
    window = input("Window <block/sliding>?: ")
    # input validation loop
    while not (window.upper() == 'BLOCK' or window.upper() == 'SLIDING'):
        window = input("Window <block/sliding>?: ")
    # if not blocks
    sliding = False
    if window.upper() == 'SLIDING':
        sliding = True #sliding window
    print_analysis(filtered, n, sliding)

