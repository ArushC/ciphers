from substitution.manualSubDecoder import special_replace, print_special_frequency_analysis, \
color, clean_message, print_with_bolds
from cryptanalysis.ngramFrequencyAnalysis import break_into_ngrams_with_remainders, get_distinct_ngrams
from polyalphabetic import probableKeyLengths
import re, ast, math, sys
from miscellaneous import pyperclip
from substitution.caesarCipher import decrypt

BOLD_CHAR = '‡'

nonletters = re.compile('[^a-zA-Z]')
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#Interactive program to manually solve a Vigenere cipher

#VIEW-COLUMN FUNCTIONS -------------------------------------------------------------------------------------------
#PRECONDITION: message is [A-Z], all uppercase (no foreign characters)
#ex. ABCDEFG, key = 3
#prints: A  B  C
#        D  E  F
#        G
#        1  2  3
def print_columns_with_bolds(message, key, letter_shifts=[], bold_char=BOLD_CHAR):
    #print the letter shifts
    print_letter_shifts(letter_shifts)
    #print(color.BOLD + ' ' + color.END, end='')
    #print the actual columns
    i = 0
    j = 0
    while i < len(message):

        if i < len(message) - 1 and message[i+1] == BOLD_CHAR:
            print(color.RED + color.BOLD, end='')
            print("%-4s" % message[i], end='\n' if j % key == key - 1 else '')
            print(color.END, end='')
            i += len(bold_char) + 2
        else:
            print("%-4s" % message[i], end='\n' if j % key == key - 1 else '')
            i += 1

        j += 1

    #if there are remainders, go to the next line
    if len(clean_message(message, bold_char)) % key != 0: print()
    #print row labels
    print_row_labels(key)
    print() #padding


def print_letter_shifts(letter_shifts):
    #print letter shifts at the top
    #this is the key that was used to encode the Vigenere cipher
    print(color.BOLD + '\n', end='')
    for i in range(len(letter_shifts)):
        print("%-4s" % (letter_shifts[i] if letter_shifts[i] else ''), end='\n' if i == len(letter_shifts) - 1 else '')
    print(color.BOLD+ '\n' + color.END, end='') #this filler line is needed to nullify the bold effect

def print_row_labels(key):
    # add row labels (bold blue in color)
    print(color.BLUE + color.BOLD, end='')
    for i in range(key):
        print("%-4s" % (i + 1), end='\n' if i == key - 1 else '')
    print(color.END, end='')
    print()

#returns the nth column in the message
def get_nth_column(message, key, n, bold_char=BOLD_CHAR):
    result = []
    i = 0  # i = letter index
    j = 0  # j = n-index
    while i < len(message):

        if i < len(message) - 1 and message[i + 1] == bold_char:  # if this char is bolded
            if j % key == n - 1:
                result.append(message[i:i + len(bold_char) + 2]) #if it is in this column
                #then append it with the abstraction
            #either way, letter index goes up by 3
            i += len(bold_char) + 2

        else:
            if j % key == n - 1:
                result.append(message[i])  #if normal char is in column append it normally
            i += 1

        j += 1 #either way, n-index increases because no characters are being skipped

    return ''.join(result)

def print_nth_column_frequencies(message, key, n):
    nth_column = get_nth_column(message, key, n)
    print_special_frequency_analysis(nth_column, default_input='Y') if not BOLD_CHAR in nth_column else \
    print_special_frequency_analysis(nth_column, bold_letters=get_distinct_ngrams(message, n=1), default_input='Y')


#returns the message with the nth column shifted & bolded
def shift_nth_column(message, key, n, bold_char=BOLD_CHAR):
    original_nth_column = get_nth_column(message, key, n)
    char = input("Enter character to replace: ").upper()
    #input validation
    while not char in clean_message(original_nth_column, BOLD_CHAR):
        char = input("Please enter a character that is in column #%d: " %n)

    replacement = input("Enter replacement character: ").upper()
    #more input validation
    while not replacement or replacement not in ALPHABET:
        replacement = input("Please enter a valid replacement character: ")

    shift = (ALPHABET.find(char) - ALPHABET.find(replacement)) % len(ALPHABET)
    letter_shift = ALPHABET[shift]
    new_nth_column = decrypt(shift, clean_message(original_nth_column, BOLD_CHAR))

    #finally, get the resultant message
    result = []
    i = 0
    j = 0
    c_index = 0
    while i < len(message):
        if i < len(message) - 1 and message[i + 1] == bold_char:  # if a letter is bolded
            if j % key == n - 1: #if a letter is in the column
                result.append(new_nth_column[c_index] + bold_char + message[i + len(bold_char) + 1])
                c_index += 1
            else: #otherwise if it is not in the column
                result.append(message[i: i + len(bold_char) + 2]) #make sure to add the bold abstraction
            i += len(bold_char) + 2
        elif j % key == n - 1:
            #otherwise do the normal single-letter replacements
            result.append(new_nth_column[c_index] + bold_char + message[i])
            c_index += 1
            i += 1
        else:
            result.append(message[i])
            i += 1

        j += 1

    return letter_shift, ''.join(result) #NOTE: two return values

#returns the message with the nth column reverted
def revert_nth_column(message, key, n, bold_char=BOLD_CHAR):
    result = []
    i = 0 #i = letter index
    j = 0 #j = n-index
    while i < len(message):

        if i < len(message) - 1 and message[i + 1] == bold_char: #if this char is bolded
            if j % key == n - 1: #if in the column, append the reverted portion only
                result.append(message[i + len(bold_char) + 1])
            else:
                #otherwise append the full abstraction
                result.append(message[i: i + len(bold_char) + 2])
            i += len(bold_char) + 2 #skip 3 chars
        else:
            result.append(message[i]) #otherwise it is part of the result
            i += 1

        j += 1

    return ''.join(result)


#VIEW ROW FUNCTIONS -----------------------------------------------------------------------------------------------------

#generates a representation of the message in which punctuation is preserved
#and the message is viewed in the horizontal viewing window
#based on the original message and the columns-bolded message
def convert_to_rows_message(original_message, columns_message, bold_char = BOLD_CHAR):
    result = []
    o_index = 0
    c_index = 0
    for o_index in range(len(original_message)):
        if original_message[o_index].upper() in ALPHABET: #if valid letter
            if c_index < len(columns_message) - 1 and columns_message[c_index + 1] == bold_char: #if a bolded character
                result.append(columns_message[c_index: c_index + len(bold_char) + 2].lower()
                    if original_message[o_index].lower() == original_message[o_index] else
                columns_message[c_index: c_index + len(bold_char) + 2]) #append to result (including abstraction)
                #if it is lowercase in the message, append lowercase abstraction, otherwise, append uppercase
                c_index += len(bold_char) + 2
            else:
                result.append(columns_message[c_index].lower() if original_message[o_index].lower()
                == original_message[o_index] else columns_message[c_index]) #otherwise append one character alone
                c_index += 1
        else:
            result.append(original_message[o_index])

    return ''.join(result)


def print_highlighted_message(original_message, columns_message, key, n, highlight_color=color.BLUE + color.BOLD):

    message = clean_message(convert_to_rows_message(original_message, columns_message))

    j = 0
    for i in range(len(message)):
        if message[i].upper() in ALPHABET: #if a valid character
            if j % key == n - 1: #if in the column
                print(highlight_color + message[i] + color.END, end='') #print highlighted
            else:
                print(message[i], end='') #otherwise print normal
            j += 1 #increment j-index
        else:
            print(message[i], end='') #print normal even if message[i] is not in ALPHABET

    print()

    
def main(ciphertext: str):

    print()
    #check to see if ciphertext is a save list
    try:
        parts = ast.literal_eval(ciphertext)
        #extract data from a saved list (if that is the input)
        ciphertext, columns, letter_shifts, view_columns = parts[0], parts[1], parts[2], parts[3]
        key = len(letter_shifts)
        #do the initial printout
        print_columns_with_bolds(columns, key, letter_shifts) if view_columns else \
            print_with_bolds(convert_to_rows_message(ciphertext, columns) + "\n")

    except (SyntaxError, ValueError):

        #show probable key lengths output
        print(probableKeyLengths.print_probable_key_lengths(msg=ciphertext))
        key = input("Based on the output above, what do you think is the key length?: ")
        #input validation
        while not (key.isnumeric() and 0 < int(key) < len(ciphertext)):
            key = input("Please enter a valid key length: ")

        key = int(key) #key str --> int. This is also the # of columns

        print() #padding
        print("VIGENERE MANUAL DECRYPTION, L = %d" %key)
        columns = re.sub(nonletters, '', ciphertext).upper() #convert to uppercase & remove spaces for columns view
        print_columns_with_bolds(columns, key)
        # boolean to indicate viewing window
        view_columns = True
        letter_shifts = ['?'] * key
        print()  # padding
        print()
        
   
    while True:   #main loop  

        character = input("""Enter a column number [1 - %d]
F) view overall frequencies of original message
V) change viewing window
R) reset message
Q) save and quit\n""" %key)
        
        #input validation
        while not (character.isnumeric() or character.upper() in 'FVRQ'):
            character = input("Please enter a valid column number or 'F', 'V', 'R', or 'Q': ")

        if character.isnumeric():
            
            #input validation
            while not (0 < int(character) <= key):
                try:
                    character = input("Please enter a valid column number: ")
                except TypeError:
                    continue

            n = int(character)
            print_columns_with_bolds(columns, key, letter_shifts) if view_columns else \
                print_with_bolds("\n" + convert_to_rows_message(ciphertext, columns) + "\n")

            while True:
                print(color.BOLD + "COLUMN #%d: " %n + color.END, end='')
                print_with_bolds(get_nth_column(columns, key, n))
                print() #padding
                character_2 = input("""F) View frequencies
H) highlight column in original message
S) Shift
R) Revert
B) Go Back\n""")

                while not character_2.upper() in 'HFSRB':
                    character_2 = input("Please enter 'F', 'H', 'S', 'R', or 'B': ")

                if character_2.upper() == 'H':
                    print()
                    print_highlighted_message(ciphertext, columns, key, n)
                    print()
                    continue
                elif character_2.upper() == 'B': #go back
                    break
                elif character_2.upper() == 'F': #frequencies
                    print_nth_column_frequencies(columns, key, n)
                    continue #printing after this will hide the frequency analysis
                elif character_2.upper() == 'S': #shift
                    nth_letter, m_new = shift_nth_column(columns, key, n)
                    letter_shifts[n-1] = nth_letter
                    columns = m_new
                else: #revert
                    columns = revert_nth_column(columns, key, n)
                    letter_shifts[n-1] = '?'
                #print out the changed columns
                print_columns_with_bolds(columns, key, letter_shifts, BOLD_CHAR) if view_columns else \
                print_with_bolds("\n" + convert_to_rows_message(ciphertext, columns, BOLD_CHAR) + "\n")
                print()
            #do this even if user chooses "Go Back" so they don't have to scroll up
            print_columns_with_bolds(columns, key, letter_shifts, BOLD_CHAR) if view_columns else \
                print_with_bolds("\n" + convert_to_rows_message(ciphertext, columns, BOLD_CHAR))
            print()


        elif character.upper() == 'Q':
            print()  # padding
            print("Your message: ", end='')
            print_with_bolds(convert_to_rows_message(ciphertext, columns, BOLD_CHAR))
            print("Key = " + color.BOLD + ''.join(letter_shifts) + color.END, end='')
            print()# even more padding
            save_list = str([ciphertext, columns, letter_shifts, view_columns])
            print("Enter this next time to resume <copied to clipboard>: " + save_list)
            pyperclip.copy(save_list)
            sys.exit(0)


        elif character.upper() == 'V':
            print() #padding
            view_columns = not view_columns
            if not view_columns: #if horizontal view
                print("Window changed to "  + color.BOLD + "HORIZONTAL VIEWING WINDOW: " + color.END)
                print()
                print_with_bolds(convert_to_rows_message(ciphertext, columns, BOLD_CHAR))
                print()
            else: #otherwise if columns view
                print("Window changed to " + color.BOLD + "COLUMNS VIEW: " + color.END)
                print_columns_with_bolds(columns, key, letter_shifts, BOLD_CHAR)


        elif character.upper() == 'R':
            print()
            are_you_sure = input("Are you sure you would like to reset? This will erase all of your current progress <y/n>?: ")
            #input validation
            while not are_you_sure.upper() in 'YN':
                are_you_sure = input("Reset <y/n>?: ")

            if are_you_sure.upper() == 'N':
                print()
                continue
            else:
                #set back to defaults
                start_over = input("Would you like to start over completely and try with a different key <y/n>?: ")
                #more input validation
                while not start_over.upper() in 'YN':
                    start_over = input("Reset <y/n>?: ")

                if start_over.upper() == 'N':
                    columns = re.sub(nonletters, '', ciphertext).upper()
                    letter_shifts = ['?'] * key
                    print_columns_with_bolds(columns, key, letter_shifts, BOLD_CHAR) if view_columns else \
                        print_with_bolds(convert_to_rows_message(ciphertext, columns, BOLD_CHAR))
                    continue

                else: #starting over completely -- make a recursive call to the main function
                    main(ciphertext)

        elif character.upper() == 'F':
            print_special_frequency_analysis(ciphertext, default_input='Y')
            print()
            continue


if __name__ == '__main__':
    C = input("Enter a message: ")
    main(C)
