from cryptanalysis.chiSquaredTest import calculate_chi_squared
from englishDetection import ngramScore, englishScore
from substitution import caesarCipher
from substitution.manualSubDecoder import color
from miscellaneous import pyperclip
import re, random
from polyalphabetic import probableKeyLengths, vigenereCipher
from polyalphabetic.manualVigenereDecoder import convert_to_rows_message

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def decrypt(ciphertext: str, columns, lower, upper, max_failures=1000):

    entries = []
    fitness = ngramScore.ngram_score(ngramScore.QUADGRAMS)
    num_of_failures = 0

    for key in range(lower, upper + 1):

        best_key = get_initial_key(columns, key)
        best_plaintext = vigenereCipher.decrypt(best_key, columns)
        best_score = fitness.score(best_plaintext)

        entries.append((best_score, best_key, best_plaintext))
        print("%-10.2f %-30s %-10s" % (best_score, best_key,
                                       convert_to_rows_message(ciphertext, best_plaintext)))

        while num_of_failures <= max_failures:
            new_key = get_new_key(best_key)
            new_plaintext = vigenereCipher.decrypt(new_key, columns)
            new_score = fitness.score(new_plaintext)

            if new_score > best_score:

                entry = (new_score, new_key, new_plaintext)
                entries.append(entry)
                #print it out
                print("%-10.2f %-30s %-10s" % (new_score, new_key,
                                               convert_to_rows_message(ciphertext, new_plaintext)))
                #update best
                best_key = new_key
                best_plaintext = new_plaintext
                best_score = new_score

            else:
                num_of_failures += 1

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

    pyperclip.copy(convert_to_rows_message(ciphertext, entries[0][2]))


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
    decrypt(msg, columns, lower, upper)

if __name__ == '__main__':
    main()
