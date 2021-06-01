from transposition.ngramTransposition import decrypt_horizontal, decrypt_vertical, convert_to_tuple
from random import randrange
from copy import deepcopy
from numpy.random import permutation
from itertools import combinations
from substitution.manualSubDecoder import color
from englishDetection import ngramScore, englishScore

#decrypts a ciphertext by using a custom algorithm
#Algorithm doesn't work 100% of the time, somewhat unpredictable
#It is kind of like bogosort: https://en.wikipedia.org/wiki/Bogosort

def decrypt(ciphertext, lowerBound, upperBound, n=1, direction='H', num_of_decryptions=10, num_of_times=200,
            fitness_score=ngramScore.ngram_score(ngramScore.QUADGRAMS).score): #this is the default fitness score

    decryptMessage = decrypt_horizontal if direction.upper() == 'H' else decrypt_vertical

    scores_list = []
            
    #generate two random indexes
    for key in range(lowerBound, upperBound + 1):
        #max num of allowed failures (new score not greater than old)
        #randomly choose a starting initial permutation (the "best" permutation only initially)
        best_perm = list(permutation(key))
        #initial "best" is decryption with the initial permutation
        best_plaintext = decryptMessage(key=tuple(best_perm), message=ciphertext)
        best_score = fitness_score(best_plaintext)
        #add initial as an entry
        scores_list.append((best_score, best_perm, best_plaintext))
        g = get_switched_permutations(best_perm)
        for i in range(num_of_times):
           entries = []
           for j in range(len(g)):
               new_perm = switch(best_perm, g[j][0], g[j][1])
               new_plaintext = decryptMessage(key=tuple(new_perm), message=ciphertext)
               new_score = fitness_score(new_plaintext)
               entry = (new_score, new_perm, new_plaintext)
               entries.append(entry)

           entries.sort(key=lambda x: x[0], reverse=True)
           if not entries[0][0] > best_score: #if this seems to be a possible decryption, add it to the scores-list
               best_entry = (best_score, best_perm, best_plaintext)
               #print it out
               print("%-10.0f %-50s %-10s" % (best_score, best_perm, best_plaintext))
               if not best_entry in scores_list:
                   scores_list.append(best_entry)
               #re-randomize best values
               best_perm = list(permutation(key))
               best_plaintext = decryptMessage(key=tuple(best_perm), message=ciphertext)
               best_score = fitness_score(best_plaintext)

           else:
                best_score, best_perm, best_plaintext = entries[0][0], entries[0][1], entries[0][2]
    
    print()
    scores_list.sort(key=lambda x: x[0], reverse=True)
    return scores_list[:num_of_decryptions + 1] if len(scores_list) <= num_of_decryptions else scores_list


def print_best_solutions(scores_list):
    print(color.RED + color.BOLD + " BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%10s %15s %54s" + color.END) % ("Score:", "Key:", "Message:"))
    for i in range(10):
        try:
            print("%-5d %-15.0f %-50s %-10s" % (i+1, scores_list[i][0], str(tuple(scores_list[i][1])), scores_list[i][2]))
        except IndexError:
            break

#returns list with switched elements at two distinct indexes in a list
def switch(li, pos1, pos2):
    return_li = deepcopy(li)
    return_li[pos1], return_li[pos2] = return_li[pos2], return_li[pos1]
    return return_li

#returns a list containing all the possible index swaps on a permutation
def get_switched_permutations(perm):
    return list(combinations(range(len(perm)), 2))


def main():
    message = input("Enter a message: ")
    remove = input("Remove spaces? [y/n]: ")
    if remove == 'y':
        message = ''.join(message.split())
    direction = input("horizontal or vertical <h/v>?: ").upper()
    n = int(input("n = "))
    lower = int(input("Lower bound: "))
    upper = int(input("Upper bound: "))
    num_of_times = int(input("How many iterations for each permutation length?: "))

    print_best_solutions(decrypt(message, lower, upper, n, direction, num_of_times,
    fitness_score= lambda x: englishScore.english_word_score(x, englishScore.COMMON_WORDS, 2)))
    # fitness score can be changed! Sometimes works better with ngram logarithmic probabilities, n = 3
            

if __name__ == '__main__':
    main()
