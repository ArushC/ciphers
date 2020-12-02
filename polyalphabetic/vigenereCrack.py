from cryptanalysis.chiSquaredTest import calculate_chi_squared
from englishDetection import ngramScore, englishScore
from substitution import caesarCipher
from substitution.manualSubDecoder import color
import re, random
from englishDetection.ngramScore import QUADGRAMS
from polyalphabetic import probableKeyLengths, vigenereCipher
from polyalphabetic.manualVigenereDecoder import convert_to_rows_message

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def decrypt_statistical(ciphertext: str, columns, lower, upper, fitness_file = ngramScore.QUADGRAMS):

    entries = []
    fitness = ngramScore.ngram_score(fitness_file)
    num_of_failures = 0

    for key in range(lower, upper + 1):

        best_key = get_initial_key(columns, key)
        best_plaintext = vigenereCipher.decrypt(best_key, columns)
        best_score = fitness.score(best_plaintext)

        entries.append((best_score, best_key, best_plaintext))
        print("%-10.2f %-30s %-10s" % (best_score, best_key,
                                       convert_to_rows_message(ciphertext, best_plaintext)))

    print()  # padding
    # could return this...
    entries.sort(key=lambda x: x[0], reverse=True)

    # but let's just print directly
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%12s %13s %34s" + color.END) % ("Score:", "Key:", "Message:"))
    for i in range(10):
        try:
            print("%-5d %-15.2f %-30s %-10s" % (i + 1, entries[i][0], ''.join(entries[i][1]),
                                          convert_to_rows_message(ciphertext, entries[i][2])))
        except IndexError:
            break

#decrypts a Vigenere cipher using quadragram statistics, uses algorithm described at:
#http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher-part-2/
def decrypt_with_child_keys(ciphertext: str, columns, lower, upper, fitness_file = QUADGRAMS):

    entries = []
    fitness = ngramScore.ngram_score(fitness_file)

    for key_length in range(lower, upper + 1):
        print("Trying keys, key length = " + str(key_length))
        overall_best_key = 'A' * key_length
        overall_best_plaintext = columns
        overall_best_score = fitness.score(columns)

        count = 0 #count tracks the number of times that a shift resulted in no improvement
        i = 0 #i tracks index of the letter to be shifted
        while count < key_length: #while the loop hasn't gone through one full cycle, try to decode
            best_plaintext = overall_best_plaintext
            best_score = fitness.score(best_plaintext)
            best_shifted_key = overall_best_key
            improvement = False
            #for every shift from 1 to 25
            for shift in range(1, len(ALPHABET)):
                shifted_key = get_shifted_alphabet(overall_best_key, i, shift)
                new_plaintext = vigenereCipher.decrypt(shifted_key, columns)
                new_score = fitness.score(new_plaintext)
                if new_score > best_score:
                    best_plaintext = new_plaintext
                    best_score = new_score
                    best_shifted_key = shifted_key
                    print(best_shifted_key)
                    improvement = True

            count = count + 1 if not improvement else 0
            i = i + 1 if not (i == key_length - 1) else 0

            overall_best_plaintext = best_plaintext
            overall_best_score = best_score
            overall_best_key = best_shifted_key

        entries.append((key_length, overall_best_score, overall_best_key, overall_best_plaintext))
        print() #padding

    entries.sort(key=lambda x: x[1], reverse=True) #could return this...
    print() #padding
    # but let's just print directly
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%19s %12s %10s %52s" + color.END) % ("Key Length: ", "Score:", "Key:", "Message:"))
    for i in range(10):
        try:
            print("%-16d %-6d %-14.2f %-48s %-10s" % (i + 1, entries[i][0], entries[i][1], ''.join(entries[i][2]),
                                                convert_to_rows_message(ciphertext, entries[i][3])))
        except IndexError:
            break


def get_shifted_alphabet(best_key, i, shift):
    return best_key[:i] + caesarCipher.encrypt(shift, best_key[i]) + best_key[i + 1:]


def get_new_key(best_key): #randomly shift one of the letters in the key to get the new key

    index = random.randrange(0, len(best_key))
    shift = random.randrange(0, len(ALPHABET))

    new_key = best_key[0: index] + caesarCipher.decrypt(shift, best_key[index])
    if index != len(best_key) - 1:
        new_key += best_key[index + 1:]

    return new_key

#returns the initial key based on chi-squared values of the 'columns' in the message
#returns the ACTUAL KEY that was used to encrypt the message the majority of the time, when the value for n is chosen correctly
def get_initial_key(msg: str, n):

    final_entries = []
    for i in range(n):
        column = msg[i::n]
        column_entries = []
        for shift in ALPHABET:
            decrypted = caesarCipher.decrypt(shift, column, ALPHABET)
            column_entries.append((calculate_chi_squared(decrypted), shift))
        column_entries.sort(key=lambda x: x[0])
        final_entries.append(column_entries[0][1])

    return ''.join(final_entries)


def main():

    msg = input("Enter a message: ")
    print() #padding
    columns = re.sub('[^A-Za-z]', '', msg).upper()

    probableKeyLengths.print_probable_key_lengths(columns, max_period=52)
    print()
    lower = int(input("Lower bound: "))
    upper = int(input("Upper bound: "))
    print() #more padding
    char = input("""
Decryption mode:

S) statistical (automatic)
T) thorough search (longer)

""")
    if char.upper() == 'S':
        decrypt_statistical(msg, columns, lower, upper)
    else:
        decrypt_with_child_keys(msg, columns, lower, upper)

if __name__ == '__main__':
    main()
