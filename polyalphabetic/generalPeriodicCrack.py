
from englishDetection import ngramScore
from substitution.homophonicCrack import get_putative_key
from substitution import substitutionCipher
from random import randrange
from polyalphabetic import probableKeyLengths
from substitution.substitutionCrack import switch
import re

#This is an implementation of the pseudocode given in this paper: https://eprint.iacr.org/2020/302.pdf
#WORD OF WARNING: this takes quite a while to run. The code was originally implemented in C, but in Python it is
#approximately 400 times slower. To combat this, decrease the value of the parameter big_limit passed into the function.
#The downside to this is that the result will probably have less accuracy. Otherwise, just wait a couple of hours.
def break_general_periodic_cipher(ciphertext, period, big_limit=None, small_limit=None, num_of_decryptions=10,
                                  fitness_file=ngramScore.TRIGRAMS):

    fitness = ngramScore.ngram_score(fitness_file)
    BIG_LIMIT = big_limit if big_limit != None else round(500000 * period * period/len(ciphertext)) #decreased BIG_LIMIT by a factor of 10
    SMALL_LIMIT = small_limit if small_limit != None else 1000

    ciphertext_parts = get_ciphertext_slices(ciphertext, period)
    parent = [get_putative_key(c_part) for c_part in ciphertext_parts]
    plaintext = decrypt(ciphertext, parent)
    best_fitness = fitness.score(plaintext)
    best_key = parent.copy()

    for big_count in range(BIG_LIMIT):
        for i in range(period):

            parent[i] = substitutionCipher.generate_random_alphabet()
            plaintext = decrypt(ciphertext, parent)
            parent_fitness = fitness.score(plaintext)
            count = 0

            while count < SMALL_LIMIT:

                child = parent.copy()
                j = randrange(0, 26)
                k = randrange(0, 26)
                swap(child, i, j, k)
                plaintext = decrypt(ciphertext, child)
                child_fitness = fitness.score(plaintext)

                if child_fitness > parent_fitness:
                    parent = child
                    parent_fitness = child_fitness
                    count = 0
                else:
                    count += 1

                if child_fitness > best_fitness:
                    best_fitness = child_fitness
                    best_key = child
                    big_count = 0
                else:
                    big_count += 1

            print("...")

    return best_key, decrypt(ciphertext, best_key)

#returns a list containing the 1st, 2nd, ..., periodth slices of a message that were encrypted w/
#separate substitution ciphers
def get_ciphertext_slices(ciphertext, period):

    res = []

    for i in range(period):
        res.append(ciphertext[i::period])

    return res

#helper function to swap the jth and kth elements of the ith element in the child key
def swap(child, i, j, k):

    part_to_swap = child[i]
    swapped = switch(part_to_swap, j, k)
    child[i] = swapped

def get_message_from_ciphertext_parts(ciphertext_parts):

    res = []
    for j in range(len(ciphertext_parts[0])):
        for i in range(len(ciphertext_parts)):
            try:
                res.append(ciphertext_parts[i][j])
            except IndexError:
                break
    return ''.join(res)

#encrypts a message using a list of keys as the keys for the individual substitution ciphers
def encrypt(message, keys):

    plaintext_parts = get_ciphertext_slices(message, len(keys))
    c_parts = []
    for i in range(len(plaintext_parts)):
        c_parts.append(substitutionCipher.encrypt(plaintext_parts[i], keys[i]))

    return get_message_from_ciphertext_parts(c_parts)


def decrypt(message, keys): #decryption function

    ciphertext_parts = get_ciphertext_slices(message, len(keys))
    p_parts = []
    for i in range(len(ciphertext_parts)):
        p_parts.append(substitutionCipher.decrypt(ciphertext_parts[i], keys[i]))

    return get_message_from_ciphertext_parts(p_parts)


def main():

    ciphertext = input("Enter a periodic cipher to decode: ")
    nonletters = re.compile('[^A-Za-z]')
    ciphertext = re.sub(nonletters, '', ciphertext)
    print(probableKeyLengths.print_probable_key_lengths(msg=ciphertext))
    period = int(input("Period = "))
    best_key, plaintext = break_general_periodic_cipher(ciphertext, period)
    print("Plaintext: " + str(plaintext))
    print("Decryption Key: ")
    for i in range(len(best_key)):
        print("K" + str(i) + ": " + str(best_key[i]))


if __name__ == '__main__':
    main()
