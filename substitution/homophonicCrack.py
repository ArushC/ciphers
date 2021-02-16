import re, math, random
import numpy as np, time
from cryptanalysis.ngramFrequencyAnalysis import get_ngrams_with_frequencies, get_distinct_ngrams
from englishDetection.englishScore import BIGRAM_FREQUENCIES
from substitution import substitutionCrack
from substitution import substitutionCipher
from cryptanalysis.chiSquaredTest import EXPECTED

#Powerful algorithm for solving simple and homophonic substitution ciphers
#From this paper: http://www.cs.sjsu.edu/faculty/stamp/RUA/homophonic.pdf
#This is the source of the bigram frequency matrix: http://keithbriggs.info/documents/english_latin.pdf
#DISCLAIMER: the homophonic sub. solver is extremely slow, and is currently being improved for efficiency

ENGLISH_FREQUENCIES_ALPHABET = 'ETAOINSRHDLUCMFYWGPBVKXQJZ'
DEFAULT_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
nonletters = re.compile('[^A-Za-z]')

#global declarations
K = best_initial_key = best_key = None


#generate a parsed english frequencies alphabet (default english minus letters that don't appear in the alphabet)
def get_parsed_frequencies_alphabet(alphabet):

    parsed_english_frequencies_alphabet = []
    for letter in ENGLISH_FREQUENCIES_ALPHABET:
        if letter in alphabet:
            parsed_english_frequencies_alphabet.append(letter)

    return ''.join(parsed_english_frequencies_alphabet)


#generates an initial key based on frequencies of letters in the message
#note that len(putative key) must equal len(alphabet)
def get_putative_key(msg, alphabet=DEFAULT_ALPHABET):

    msg = re.sub(nonletters, '', msg).upper()
    frequencies = get_ngrams_with_frequencies(msg, n=1)
    res = [''] * len(alphabet)

    parsed_english_frequencies_alphabet = get_parsed_frequencies_alphabet(alphabet)
    letters_that_appear_zero_times = alphabet

    i = 0
    for letter in frequencies.keys():
        res[alphabet.find(parsed_english_frequencies_alphabet[i])] = letter
        letters_that_appear_zero_times = letters_that_appear_zero_times.replace(letter, '')
        i += 1


    #for the letters that appear 0 times in the message, add them to the end
    for i in range(len(res)):
        if not res[i]:
            res[i] = letters_that_appear_zero_times[0]
            letters_that_appear_zero_times = \
                letters_that_appear_zero_times.replace(letters_that_appear_zero_times[0], '')

    return ''.join(res)

#returns the English bigram frequency matrix for a given alphabet and message length
#example: if the alphabet is 'AB' and the message length is 10
#      A          B
#A  freq(AA)  freq(AB)   --> multiply this matrix by a scalar factor of 10
#B  freq(BA)  freq(BB)
def get_expected_bigram_frequency_matrix(msg_length, alphabet=DEFAULT_ALPHABET):

    res = np.zeros(shape=(len(alphabet), len(alphabet)), dtype=float)

    for line in open(BIGRAM_FREQUENCIES):
        bigram, frequency = line.split()
        frequency = float(frequency)
        first_letter = bigram[0]
        second_letter = bigram[1]

        if first_letter in alphabet and second_letter in alphabet:
            first_letter_index = alphabet.find(first_letter)
            second_letter_index = alphabet.find(second_letter)
            res[first_letter_index][second_letter_index] = frequency * msg_length

    return res

#returns a matrix of bigram frequencies observed in a message
#example: message = 'ABAB', alphabet = 'AB'
#'AB' occurs 2 times and 'BA' occurs once, so the frequency matrix will be:
#      A   B
#A     0   2
#B     1   0
def get_observed_bigram_frequency_matrix(msg, alphabet=DEFAULT_ALPHABET):

    bigram_counts = get_ngrams_with_frequencies(msg, n=2, sliding=True)

    res = np.zeros(shape=(len(alphabet), len(alphabet)), dtype=float)

    for bigram, bigram_count in bigram_counts.items():

        first_letter = bigram[0]
        second_letter = bigram[1]
        res[alphabet.find(first_letter)][alphabet.find(second_letter)] = bigram_count

    return res

#returns the bigram score. Formula given at the bottom of page 10 of the paper
def get_bigram_score(observed, expected, alphabet=DEFAULT_ALPHABET):

    difference = observed - expected
    abs_difference = np.array(list((map(lambda x: abs(x), difference))))
    score = sum(sum(abs_difference)) #add together all the values in the distance function matrix
    return score

#returns the resultant key and matrix from swapping two rows and columns in the bigram matrix
def swap(letter_index_1, letter_index_2, observed_frequency_matrix, key):
    # switch the rows in the matrix

    x = observed_frequency_matrix.copy()

    x[[letter_index_1, letter_index_2]] = \
        x[[letter_index_2, letter_index_1]]
    #switch the columns in the matrix
    x[:, [letter_index_1, letter_index_2]] = \
        x[:, [letter_index_2, letter_index_1]]
    #switch the corresponding letters in the alphabet
    new_key = substitutionCrack.switch(key, letter_index_1, letter_index_2)
    return x, new_key

#implements the series of swaps described in the middle of page 10
#returns the key that was used to decrypt the substitution cipher
#continues the (26 choose 2) swaps until no improvement is detected
def fast_substitution_solve(msg, alphabet=DEFAULT_ALPHABET):

    #first, decrypt using the putative key
    best_key = get_putative_key(msg, alphabet)
    initial_plaintext = substitutionCipher.decrypt(msg, best_key, default_alphabet=alphabet)
    observed = get_observed_bigram_frequency_matrix(initial_plaintext, alphabet)
    expected = get_expected_bigram_frequency_matrix(len(initial_plaintext), alphabet)
    best_matrix = observed
    best_score = get_bigram_score(observed, expected, alphabet)

    improvement = True

    while improvement:

        improvement = False

        for round in range(1, len(alphabet)):
            for start_swap_index in range(1, len(alphabet) - round + 1):
                letter_index_1 = start_swap_index - 1
                letter_index_2 = start_swap_index + round - 1
                matrix, new_key = swap(letter_index_1, letter_index_2, best_matrix, best_key)
                #what makes this algorithm fast is that the score can be computed without decoding each individual plaintext
                new_score = get_bigram_score(matrix, expected, alphabet)
                if new_score < best_score:
                    best_matrix = matrix
                    best_key = new_key
                    best_score = new_score
                    improvement = True


    return best_key

#below are the helper functions and code for the homophonic substitution cipher

#returns the initial frequency distribution for a given value of n > 26
def get_initial_frequency_distribution(n, alphabet=DEFAULT_ALPHABET):

    #algorithm: calculate the expected number of symbols that should map to each letter
    #from most frequent to least frequent occuring letter in the english alphabet
    #once we run out of symbols, we stop. The result is the initial frequency distribution

    expected_symbol_counts = [1] * len(alphabet)
    parsed_english_frequencies_alphabet = get_parsed_frequencies_alphabet(alphabet)

    additional_symbols = n - len(alphabet)

    for letter in parsed_english_frequencies_alphabet:

        expected_symbol_letter_count = round(EXPECTED[letter] * n)

        if expected_symbol_letter_count - 1 > additional_symbols: #ex. if n = 27, 'E' --> 3.24 expected symbols
        #but since only one additional symbol is available, add only the available symbol to the 'E' count
            expected_symbol_counts[alphabet.find(letter)] += additional_symbols
            break

        else:
            expected_symbol_counts[alphabet.find(letter)] += expected_symbol_letter_count - 1
            additional_symbols -= expected_symbol_letter_count - 1

    return expected_symbol_counts

def get_initial_frequency_distribution_from_key(key, alphabet=DEFAULT_ALPHABET):

    res = [key.count(letter) for letter in alphabet]
    return res

#this is a straight translation of the pseudocode given on page 26 of the paper
#additional return value: the distinct symbols in the message (for decryption later)
def outer_hill_climb(message, alphabet=DEFAULT_ALPHABET, initial_key=None):

    #important note: pseucocode describes a 1-based index coordinate system
    #so need to standardize by subtracting one from the indexes in all the swaps

    global best_key
    global best_initial_key

    distinct_symbols = ''.join(get_distinct_ngrams(message, n=1))
    n = len(distinct_symbols)
    D_C = get_observed_bigram_frequency_matrix(message, alphabet=distinct_symbols)
    message_length = len(message)
    m_values = get_initial_frequency_distribution(n, alphabet)

    if not initial_key:
        m_values = get_initial_frequency_distribution(n, alphabet)
        best_score = random_initial_key(m_values, D_C, message_length, alphabet)
    else:
        best_initial_key = initial_key
        m_values = get_initial_frequency_distribution_from_key(initial_key, alphabet)
        initial_decryption = decode_homophonic(message, distinct_symbols, initial_key)
        best_score = get_bigram_score(get_observed_bigram_frequency_matrix(initial_decryption, alphabet),
                                      get_expected_bigram_frequency_matrix(message_length, alphabet))
    best_key = best_initial_key

    for i in range(1, len(alphabet)):
        for j in range(1, len(alphabet) - i + 1):

            if m_values[j - 1] != 0:
                m_prime_values = outer_swap(m_values, j + i - 1, j - 1)
            else:
                continue #cannot swap the values if the second value is equal to zero (no negative numbers)

            score = random_initial_key(m_prime_values, D_C, message_length, alphabet)

            if score < best_score:
                m_values = m_prime_values
                best_score = score
                best_key = best_initial_key
            else:
                if m_values[j - 1] != 0:
                    m_prime_values = outer_swap(m_values, j + i - 1, j - 1)
                else:
                    continue

                score = random_initial_key(m_prime_values, D_C, message_length, alphabet)
                if score < best_score:
                    m_values = m_prime_values
                    best_score = score
                    best_key = best_initial_key

        print('$', end='')

    return distinct_symbols, best_key

#returns a list on which the outer swap has been performed -- see paper bottom of page 26
def outer_swap(m, i, j):
    m_prime = m.copy()
    m_prime[i] += 1
    m_prime[j] -= 1
    return m_prime

def random_initial_key(n_values, D_C, message_length, alphabet=DEFAULT_ALPHABET, R=1):

    global K #add this so that the outer value of K is referenced
    global best_initial_key

    best_initial_score = math.inf

    for r in range(1, R + 1):
        K = get_random_initial_key(n_values, alphabet)
        D_P = get_D_P(D_C, K, alphabet)
        initial_score = inner_hill_climb(D_P, D_C, message_length, alphabet)
        if initial_score < best_initial_score:
            best_initial_score = initial_score
            best_initial_key = K

    return best_initial_score

#switch the rows/columns in a copy of D_C, and then use the function to get the new D_P from D_C and the key
#if either of the letters that are being swapped appear more than once in the key (homophonic special case)
#otherwise, just do a basic row-column switch
def homophonic_swap(letter_index_1, letter_index_2, D_P, D_C, key, alphabet=DEFAULT_ALPHABET):

    if key.count(key[letter_index_1]) > 1 or key.count(key[letter_index_2]) > 1:
        # note: D_C doesn't actually get modified by the swap function
        # the swapping is done on a copy of D_C, and the result is used to determine D_P
        swapped_D_C, swapped_key = swap(letter_index_1, letter_index_2, D_C, key)
        new_D_P = get_D_P(swapped_D_C, swapped_key, alphabet)
    else:
        #otherwise, it is just the normal swap
        new_D_P, swapped_key = swap(alphabet.find(key[letter_index_1]), alphabet.find(key[letter_index_2]), D_P, key)

    return new_D_P, swapped_key


def inner_hill_climb(D_P, D_C, message_length, alphabet=DEFAULT_ALPHABET):

    global K #must add this so the outer K value is referenced

    expected = get_expected_bigram_frequency_matrix(message_length, alphabet)
    inner_score = get_bigram_score(D_P, expected, alphabet)
    n = len(D_C) #number of symbols

    improvement = True

    # NOTE: additional swaps were added here to improve the accuracy of the inner hill climb algorithm
    # Ensures that the optimal solution will (almost) always be found from a randomly generated key,
    # allowing us to set R = 1 with reasonable confidence in the random initial key layer
    while improvement:

        improvement = False

        for i in range(1, n):
            for j in range(1, n - i + 1):
                k_prime = K
                new_D_P, new_key = homophonic_swap(j - 1, j + i - 1, D_P, D_C, k_prime, alphabet)
                new_score = get_bigram_score(new_D_P, expected, alphabet)
                if new_score < inner_score:
                    inner_score = new_score
                    K = new_key
                    D_P = new_D_P
                    improvement = True

    return inner_score

#determine the matrix D_P from D_C and a key
def get_D_P(D_C, key, alphabet=DEFAULT_ALPHABET):

    res = np.zeros(shape=(len(alphabet), len(alphabet)), dtype=float)

    bigrams_dict = dict()

    for row in range(len(D_C)):
        for column in range(len(D_C)):
            bigram = key[row] + key[column]
            try:
                bigrams_dict[bigram] += D_C[row][column]
            except KeyError: #in case the first entry for this bigram hasn't been added yet
                bigrams_dict[bigram] = D_C[row][column]

    for bigram, bigram_count in bigrams_dict.items():

        first_letter = bigram[0]
        second_letter = bigram[1]
        res[alphabet.find(first_letter)][alphabet.find(second_letter)] = bigram_count

    return res

#returns a random initial key from the values n_a, n_b, ..., n_z
def get_random_initial_key(n_values, alphabet=DEFAULT_ALPHABET):

    number_of_distinct_symbols = sum(n_values)
    k = [''] * number_of_distinct_symbols

    # generate a list of random indexes to place the components of the key
    h = list(range(number_of_distinct_symbols))
    random.shuffle(h)

    h_index = 0

    for i in range(len(n_values)):
        for j in range(n_values[i]):
            k[h[h_index]] = alphabet[i]
            h_index += 1

    return ''.join(k)


def decode_homophonic(ciphertext, distinct_symbols, key):

    res = [key[distinct_symbols.find(letter)] for letter in ciphertext]
    return ''.join(res)



def main():

    message = input("Enter a message: ")
    remove = input("Remove spaces? <y/n>: ")
    if remove.upper() == 'Y':
        message = message.replace(' ', '')

    mode = input(
'''
S) solve substitution cipher
H) solve homophonic substitution cipher
'''
    )

    while not mode.upper() in 'SH': #input validation
        mode = input("Please enter either 'S' or 'H'. ")

    if mode.upper() == 'S':
        best_key = fast_substitution_solve(message)
        print()
        print(substitutionCipher.decrypt(message, best_key))
        print("Encryption key: " + best_key)

    elif mode.upper() == 'H':
        ik = input("Decode with a specified initial key? <y/n>")
        if ik.upper() == 'Y':
            initial_key = input("Enter initial key: ").upper()
            print("Solving homophonic substitution cipher.")
            print("WARNING: this will take a while (1-2 hours). Individual $ symbols "
                  "will signal the end of 1/26 of the iterations.")
            distinct_symbols, best_key = outer_hill_climb(message, initial_key=initial_key)
        else:
            print("Solving homophonic substitution cipher.")
            print("WARNING: this will take a while (1-2 hours). Individual $ symbols "
                  "will signal the end of 1/26 of the iterations.")
            distinct_symbols, best_key = outer_hill_climb(message)

        print(decode_homophonic(message, distinct_symbols, best_key))
        print("Encryption key: " + best_key)



if __name__ == '__main__':
    main()
