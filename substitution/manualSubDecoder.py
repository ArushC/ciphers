from cryptanalysis.ngramFrequencyAnalysis import get_ngrams_with_frequencies, sum_of_appearances, \
get_distinct_ngrams, count_distinct_ngrams
from cryptanalysis import chiSquaredTest
import re, operator
from miscellaneous import pyperclip
import sys, ast, random
#declare constants
BOLD_CHAR = ''

#taken from the answer to a StackOverflow question
#https://stackoverflow.com/questions/8924173/how-do-i-print-bold-text-in-python/20210807
class color:  
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'


def print_with_bolds(ciphertext, bold_char=BOLD_CHAR):
    i = 0
    while i < len(ciphertext):
        if  ciphertext[i+1:i+len(bold_char) + 1] == bold_char:
            print(color.RED + color.BOLD + ciphertext[i] + color.END, end='')
            i += len(bold_char) + 1 #add 1 for the additional replaced letter that will follow the bold char
        else:
            print(ciphertext[i], end = '')

        i += 1
    print() #to go to next line

#REVERTS all bold chars from the ciphertext
def reset_message(ciphertext, bold_char=BOLD_CHAR):
    ciph_list = []
    i = 0
    while i < len(ciphertext):

        if i < len(ciphertext) - 1 and ciphertext[i+1] == bold_char:
            i += 2
        else:
            ciph_list.append(ciphertext[i])
            i += 1

    return ''.join(ciph_list)

#REMOVES all extraneous characters in the message that are part of the bold abstraction
#ex. message = 'A\BCDE\FG' --> ACDEG
#notice how very similar yet very different this is from reset_message
def clean_message(ciphertext, bold_char=BOLD_CHAR):
    ciph_list = []
    i = 0
    while i < len(ciphertext):
        if ciphertext[i] == bold_char:
            i += 2
        else:
            ciph_list.append(ciphertext[i])
            i += 1

    return ''.join(ciph_list)

#prints a side-by-side frequency analysis of observed and expected
def print_special_frequency_analysis(ciphertext, bold_letters=[], non_bold_letters=[], replaced_chars=[], default_input=''):
    #first --> take out all extraneous chars
    #AKA destroy the abstraction
    #wherever there is 'X/YZ' replace with 'XZ'
    ciphertext = clean_message(ciphertext)
    if not default_input: #if no default input was provided, ask for input
        letters_only = input("Analyze letters only <y/n>?: ")
        #input validation
        while letters_only.upper() not in "YN":
            letters_only = input("Analyze letters only (with 'abcd' == 'ABCD') <y/n>?: ")
        if letters_only.upper() == 'Y':
            ciphertext = re.sub('[^a-zA-Z]', '', ciphertext).upper()
    elif default_input.upper() == 'Y':
        ciphertext = re.sub('[^a-zA-Z]', '', ciphertext).upper()

    print()
    frequencies = get_ngrams_with_frequencies(ciphertext, n=1)
    #set two booleans to indicate whether observed/expected has finished printing
    completed_expected_printouts = False
    completed_observed_printouts = False
    expected_freqs = chiSquaredTest.EXPECTED
    #sort expected frequencies to get ETAOINSHRDLU etc. in that order
    sorted_ef = dict(sorted(expected_freqs.items(), key=operator.itemgetter(1), reverse=True))
    ef_alphabet = list(sorted_ef.keys())
    print("%s %45s" %(color.BOLD + "OBSERVED:", "EXPECTED:" + color.END))
    total = sum_of_appearances(ciphertext, n=1, sliding=False)
    #the main loop
    i = 0
    while i < len(ef_alphabet):
        for letter, count in frequencies.items(): #for every observed pair
            frequency = count / total #calculate the letter's frequency
            try:
                expected_letter = ef_alphabet[i] #then look at the expected letters
            except IndexError:
                completed_expected_printouts = True
            #do all the single-line printing, but only if the boolean values are both False
            if not completed_observed_printouts:
                if letter in bold_letters and letter in non_bold_letters:
                    print("%-3s" %(color.RED + color.BOLD + letter + color.END + '/' + letter), end='')
                else:
                    print("%-3s" %(color.RED + color.BOLD + letter + '  ' + color.END), end='') if letter in bold_letters \
                else print("%-3s" %letter, end='')
                print(":%5d " % count, end='')
                print("%10.2f%%" % (frequency * 100), end= '\n' if completed_expected_printouts else '')
            if not completed_expected_printouts:
                print("%24s" %(expected_letter + ": "), end='') if not completed_observed_printouts \
                else print("%44s" %(expected_letter + ":"), end='')
                print("%.2f%%" % (expected_freqs[expected_letter] * 100))
            i += 1  #increment i

        #if the inner loop finishes, then all the observed printouts have occured
        completed_observed_printouts = True
        i += 1

    print("#n: %d" % count_distinct_ngrams(ciphertext, n=1))
    print("Total appearances: %d" % sum_of_appearances(ciphertext, n=1))
    print()


#replaces every occurence of a nonbolded character with a bolded one
def special_replace(message, old, new, bold_char=BOLD_CHAR):
    # if a char is replaced with bold then it will look like this:
    # ex. message = ABCDEFAG
    #replace A with T
    #T/ABCDEFT/AG
    #/A is ignored in all cases

    i = 0
    result = []
    while i < len(message):
        bold_check_part = message[i+1:i+len(bold_char) + 1]
        #if a letter is bolded

        if bold_check_part == bold_char: #ex. B/CD --> need to skip to D
            skip_amount = len(bold_char) + 1 #skip amount = 2
            result.append(message[i: i + skip_amount + 1]) #append B/C
            i += skip_amount
        elif message[i] == old:
            result.append(new)
        else:
            result.append(message[i])

        i += 1

    return ''.join(result)


def main(ciphertext: str):

    try:
        parts = ast.literal_eval(ciphertext)
        #extract data from a saved list (if that is the input)
        ciphertext, bold_letters, non_bold_letters, replaced_characters = parts[0], parts[1], parts[2], parts[3]
    except (SyntaxError, ValueError):
        #otherwise if the input is not a list, assume that input is a normal ciphertext
        bold_letters = []
        non_bold_letters = get_distinct_ngrams(ciphertext, n=1)
        replaced_characters = []
    print()
    print_with_bolds(ciphertext)
    print()
    while True:
        character = input("Enter a character to replace,'/UNDO' to undo a character replacement, '/FREQ' to view frequencies,\
'/RESET' to undo all character replacements, or '/Q' to save & quit: ")

        if character == '/Q':
            print() #padding
            print("Your current message: ", end = '')
            print_with_bolds(ciphertext)
            print() #more padding
            save_list = str([ciphertext, bold_letters, non_bold_letters, replaced_characters])
            print("Enter this next time to resume <copied to clipboard>: " + save_list)
            pyperclip.copy(save_list)
            sys.exit(0)

        elif character.upper() == '/FREQ':
            print()
            print_special_frequency_analysis(''.join(ciphertext.split()), bold_letters, non_bold_letters, replaced_characters)
            print_with_bolds(ciphertext)
            print()
            continue

        elif character.upper() == '/RESET':
            print()
            ciphertext = reset_message(ciphertext)
            bold_letters.clear()
            non_bold_letters = get_distinct_ngrams(ciphertext, n=1)
            replaced_characters.clear()
            print_with_bolds(ciphertext)
            print()
            continue


        elif character in non_bold_letters:
            new_character = input("Enter replacement character: ")
            #intermediate ciphertext to indicate which letters are bold
            ciphertext = special_replace(ciphertext, character, new_character + BOLD_CHAR + character)
            #add an entry to replaced characters
            replaced_characters.append((character, new_character))
            #character has been bolded now -- remove from non-bolded
            non_bold_letters.remove(character)
            bold_letters.append(new_character)
            print()
            print_with_bolds(ciphertext)
            print() #one extra line of padding

        elif character.upper() == '/UNDO':
            character_to_revert = input("Enter bolded character to revert: ")
            if character_to_revert in bold_letters:
                possible_reverts = [] #a list of possible bold mappings to revert
                for i in range(len(replaced_characters)):
                    if replaced_characters[i][1] == character_to_revert:
                        possible_reverts.append(replaced_characters[i][0])

                if len(possible_reverts) == 1:
                    reverted_character = possible_reverts[0]

                else:
                    print("The bolded character %s has been used to replace: " %character_to_revert, end='')
                    print(*possible_reverts)
                    reverted_character = input("Which of those characters would you like to see nonbolded? ")
                    #input validation
                    while reverted_character not in possible_reverts:
                        reverted_character = input("Please enter one of the characters listed above: ")

                # finally, do the replacement
                ciphertext = ciphertext.replace(character_to_revert + BOLD_CHAR + reverted_character,
                                                reverted_character)
                #update bold & non-bold letters lists
                bold_letters.remove(character_to_revert)
                non_bold_letters.append(reverted_character)
                #delete entry from replaced_characters
                replaced_characters.remove((reverted_character, character_to_revert))

                print() #padding
                print_with_bolds(ciphertext)
                print() #padding

            else:
                print("Invalid input -- character entered is not among bolded letters")
                print()
                print_with_bolds(ciphertext)
                print()
                continue


        else:
            print("Invalid input -- character entered is not among nonbolded letters")
            print()
            print_with_bolds(ciphertext)
            print()
            continue


if __name__ == '__main__':
    C = input("What message will I be decoding today: ")
    main(C)
