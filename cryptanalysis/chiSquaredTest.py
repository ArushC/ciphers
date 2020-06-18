from cryptanalysis.ngramFrequencyAnalysis import get_ngrams_with_frequencies, get_distinct_ngrams
import math
from scipy.stats.distributions import chi2 #make sure to add this import in your project interpreter (add "scipy")
import re
#this is for English standard frequencies (taken from
# http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/)
EXPECTED = \
{'A' :  0.0855,       'K' :  0.0081,       'U' :  0.0268,
'B' :  0.0160,        'L' :  0.0421,        'V' :  0.0106,
'C' :  0.0316,        'M' :  0.0253,        'W' :  0.0183,
'D' :  0.0387,        'N' :  0.0717,        'X' :  0.0019,
'E' : 0.1210,        'O' :  0.0747,         'Y' :  0.0172,
'F' :  0.0218,        'P' :  0.0207,        'Z' :  0.0011,
'G' :  0.0209,        'Q' :  0.0010,        'H' :  0.0496,
'R' :  0.0633,        'I' :  0.0733,        'S' :  0.0673,
'J' :  0.0022,        'T' :  0.0894}

ENGLISH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#chi squared = SUM((observed count - expected count)^2)/expected count
#high chi squared indicates a high deviation from english frequencies
def calculate_chi_squared(msg, n=1, exp=EXPECTED):

    expected = exp.copy()
    observed = get_ngrams_with_frequencies(msg, n)

    #filter observed so that all characters --> uppercase and only characters in expected are kept
    filtered_observed = dict()
    #initialize all values in filtered_observed to 0
    for letter in expected.keys():
        filtered_observed[letter] = 0
    #then filter it
    observed_keys = list(observed.keys())
    for i in range(len(observed_keys)):
        if observed_keys[i].upper() in expected.keys():
            k = observed_keys[i].upper()
            filtered_observed[k] += observed[observed_keys[i]]

    filtered_message_length = sum(list(filtered_observed.values()))
    #calculate expected observances
    for letter in expected.keys():
        expected[letter] *= filtered_message_length
    #finally, calculate
    s = 0
    for letter in filtered_observed.keys():
        s += pow(filtered_observed[letter] - expected[letter], 2)/expected[letter]

    return s



#generates the parameter 'expected' for any string that is being compared to randomness
def generate_expected(msg, n=1, alphabet=''):

    expected = dict()
    #this is the alphabet by default (if no alphabet is provided)
    if alphabet == '':
        alphabet = ''.join(get_distinct_ngrams(msg, 1))

    expected_value = 1 / pow(len(alphabet), n)
    all_ngrams = generate_all_possible_ngrams(n, alphabet)
    for ngram in all_ngrams:
        expected[ngram] = expected_value

    return expected



#generates a list of all possible ngrams from a given alphabet
def generate_all_possible_ngrams(n, alphabet: str):
    #ex. n = 3, A = '012'                                                       #ex. n = 2, A = '012'
     #l1 = 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2  j = 1              #l1 = 0 0 0 1 1 1 2 2 2
     #l2 = 0 0 0 1 1 1 2 2 2 0 0 0 1 1 1 2 2 2 0 0 0 1 1 1 2 2 2                #l2 = 0 1 2 0 1 2 0 1 2
     #l3 = 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0 1 2

    #ex. n = 2, A = '01'                          #ex. n = 3, A = '01'
    #l1 = 0 0 1 1                                 #l1 = 0 0 0 0 1 1 1 1   1/n * # of ngrams    j = 0, a_index = 3
    #l2 = 0 1 0 1                                 #l2 = 0 0 1 1 0 0 1 1   (1/n)^2 * # of ngrams j = 1, a_index = 2
                                                  #l3 = 0 1 0 1 0 1 0 1   (1/n)^3 * # of ngrams j = 2, a_index = 1

    num_of_n_grams = pow(len(alphabet), n)
    ngrams_list = [''] * num_of_n_grams
    a_index = num_of_n_grams/len(alphabet)
    for i in range(n):
        count = 0
        s = 0
        for j in range(len(ngrams_list)):
            if count == a_index:
                count = 0
                s += 1
            count += 1
            ngrams_list[j] += alphabet[s % len(alphabet)]

        a_index /= len(alphabet)

    return ngrams_list

#this is a chi_squared test for goodness-of-fit
#it returns the chi_squared value and the p-value for the test, along with a boolean for
#whether the results are significant at the specified alpha-level
#if conditions are not satisfied a warning will be printed

def chi_squared_gf_test(msg, n=1, alphabet='', alpha=0.05, compare_to_english=False):

    sample_size = math.floor(len(msg)/n)
    #if boolean compare_to_english is true, then this test will compare against english frequencies
    expected =  EXPECTED if compare_to_english else generate_expected(msg, n, alphabet)
    # check large counts condition --> expected count >= 5
    tests_passed = True
    e = list(expected.values())
    for expected_freq in e:
        if expected_freq * sample_size < 5:
            tests_passed = False
            break
    #tests_passed = sample_size * list(expected.values())[0] >= 5 #boolean is returned to indicate whether tests passed
    chi_squared = calculate_chi_squared(msg, n, expected)
    df = len(expected) - 1
    p_value = chi2.sf(chi_squared, df)
    significance = p_value < alpha #boolean to represent whether the results are significant @ the specified alpha level
    return tests_passed, chi_squared, p_value, significance #return in order of the steps taken during hypothesis testing



def print_all_ngram_chi_squared_test_results(msg, lower_bound=1, upper_bound=1, alphabet='', alpha=0.05, compare_to_english=False):
    print()
    print("RESULTS OF CHI SQUARED TEST(S):")
    print()
    print("%-5s %-25s %-20s %-25s %15s" %("n", "Conditions checked?", "Chi-squared:", "P-value", "Significant at alpha = 0.05?"))

    for n in range(lower_bound, upper_bound + 1):
        tests_passed, chi_squared, p_value, significance = chi_squared_gf_test(msg, n, alphabet, alpha, compare_to_english)
        print("%-5d %-25s %-20.5f %-25s %15s" %(n, str(tests_passed), chi_squared, str(p_value), str(significance)))



def main():

    message = input('Enter a message: ')
    display_msg = """
E)   compare to standard English frequencies
U)   compare to uniform English distribution
N)   compare n-grams to random distribution

"""
    test_type = input(display_msg)
    #input validation
    validate_input(test_type, 'EUN')
    #check test type and print appropriate test
    if test_type.upper() == 'E':
        print_all_ngram_chi_squared_test_results(message, alphabet=ENGLISH_ALPHABET, compare_to_english=True)
    elif test_type.upper() == 'U':
        print_all_ngram_chi_squared_test_results(message, alphabet=ENGLISH_ALPHABET)
    else:
        custom_alphabet = input("Custom alphabet? (contains characters not present in the message) <y/n>: ")
        validate_input(custom_alphabet, 'YN')
        if custom_alphabet.upper() == 'Y':
            #in case the user accidentally types multiple characters in the alphabet, be ready...
            alphabet = ''.join(get_distinct_ngrams(input("Enter the alphabet:"), n=1))
        else:
            alphabet = '' #this is the input passed for the default value of the alphabet


        lower = int(input("Lower bound: n = "))
        upper = int(input("Upper bound: n = "))
        print_all_ngram_chi_squared_test_results(message, lower_bound=lower, upper_bound=upper)

    #note:
    #when cryptanalyzing
    #first compare p-values
    #if they are too small to compare (all equal to 0), then look at the chi-squared values, with a grain of salt

def validate_input(inp, valid_letters='', condition=True):
    # input validation loop
    while not inp.upper() in valid_letters and condition:
        print("Invalid input!")
        test_type = input(inp)

if __name__ == '__main__':
    main()


