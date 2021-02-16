from random import randrange
from cryptanalysis.ngramFrequencyAnalysis import get_ngrams_with_frequencies
from substitution.manualSubDecoder import color
from substitution import substitutionCipher
from englishDetection import ngramScore
from miscellaneous import pyperclip
from substitution import homophonicCrack
import re, time

#decrypts a ciphertext by using a simulated annealing algorithm
def decrypt(ciphertext, initial_alphabet=None, failures=1000, num_of_decryptions=10, fitness_file = ngramScore.QUADGRAMS):

    scores_list = []
    fitness = ngramScore.ngram_score(fitness_file)

    #generate two random indexes
    #max num of allowed failures (new score not greater than old)
    #randomly choose a starting initial permutation (the "best" permutation only initially)
    best_alph = substitutionCipher.generate_random_alphabet() if not initial_alphabet else initial_alphabet
    #initial "best" is decryption with the initial permutation
    best_plaintext = substitutionCipher.decrypt(message=ciphertext, alphabet=best_alph)
    best_score = fitness.score(best_plaintext)
    #add initial as an entry
    scores_list.append((best_score, best_alph, best_plaintext))
    failure_count = 0

    while True:
        r1 = randrange(0, len(best_alph))
        r2 = randrange(0, len(best_alph))
            #make sure r1 and r2 are not the same index
        while r1 == r2:
            r2 = randrange(0, len(best_alph))

        new_alph = switch(best_alph, r1, r2)
        new_plaintext = substitutionCipher.decrypt(message=ciphertext, alphabet=new_alph)
        new_score = fitness.score(new_plaintext)

        if new_score > best_score:
            entry = (new_score, new_alph, new_plaintext) #add a tuple entry to scores list (later will be sorted)
            if not entry in scores_list:
                scores_list.append(entry)

            #print it out
            print("%-10.2f %-30s %-10s" % (new_score, new_alph, new_plaintext))
            #also update best
            best_plaintext = new_plaintext
            best_alph = new_alph
            best_score = new_score
            failure_count = 0 #reset failure count

        else:
            if failure_count > failures: #if failed too many times, break out of the loop
                break
            failure_count += 1


    print() #padding

    scores_list.sort(key = lambda x: x[0], reverse=True)
    return scores_list[:num_of_decryptions + 1] if len(scores_list) <= num_of_decryptions else scores_list


def print_best_solutions(scores_list):
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%12s %18s %29s" + color.END) % ("Score:", "Alphabet:", "Message:"))
    for i in range(10):
        try:
            print("%-5d %-15.2f %-30s %-10s" % (i + 1, scores_list[i][0], ''.join(scores_list[i][1]),
                                           scores_list[i][2]))
        except IndexError:
            break

    pyperclip.copy(scores_list[0][2])



#returns list with switched elements at two distinct indexes in a list
def switch(alph, pos1, pos2):
    return_li = list(alph)
    return_li[pos1], return_li[pos2] = return_li[pos2], return_li[pos1]
    return ''.join(return_li)



def get_ordered_appearances(msg: str, letters_only=True): #returns an alphabet of letters in the message ordered
                                                          #by frequency of appearance

    if letters_only: #if only letters, take out all foreign chars
        msg = re.sub('[^A-Za-z]', '', msg)

    return ''.join(get_ngrams_with_frequencies(msg, n=1).keys()) #this dictionary has already been sorted


def main(message, failures=1000, initial_alphabet=substitutionCipher.generate_random_alphabet()):

    solve_speed = input("Solve using slow algorithm or fast algorithm? <s/f>: ")
    message = message.upper()
    print()  # padding
    if solve_speed.upper() == 'S':
        print_best_solutions(decrypt(message, initial_alphabet, failures))
        print()
        print("#1 best solution copied to clipboard")
    else:
        best_key = homophonicCrack.fast_substitution_solve(message)
        print(substitutionCipher.decrypt(message, best_key))
        print("Encryption Key: " + best_key)


if __name__ == '__main__':
    message = input("Enter a message: ")
    main(message)
   
