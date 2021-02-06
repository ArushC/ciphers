from itertools import permutations
from miscellaneous import pyperclip
import math, re
from cryptanalysis.ngramFrequencyAnalysis import count_distinct_ngrams, break_into_ngrams_with_remainders, \
break_into_ngrams
from englishDetection import englishScore

def main():
    message = input("Enter a message: ")
    remove = input("Remove spaces? [y/n]: ")
    if remove == 'y':
        message = message.replace(' ', '')
    direction = input("Cipher direction <horizontal/vertical>?: ")
    #additional input --> n for the n-grams
    n = int(input("n = "))
    crack = input("Crack code? <y/n>: ")
    if crack == 'y':
        lower_bound = int(input("Enter lower bound: "))
        higher_bound = int(input("Enter higher bound: "))
        print()
        display_best_decryptions(message=message, direction=direction, lowerBound=lower_bound,
        higherBound=higher_bound, num_of_decryptions=10, n=n)

    else:
        raw_inp = input("Enter key: ")
        try:
            #if converting it to a tuple doesn't work
            key = get_permutation((convert_to_tuple(list(raw_inp))))
        except ValueError:
            #it must be a string key
            key = key_permutation(raw_inp)

        mode = input("Mode <encrypt/decrypt>?: ")
        filler = input("Filler = ")
        if mode == 'encrypt':
            if direction == 'horizontal':
                ciphertext = encrypt_horizontal(message, key, n, filler)
            else:
                ciphertext = encrypt_vertical(message, key, n, filler)
        else:
            if direction == 'horizontal':
                ciphertext = decrypt_horizontal(message, key, n)
            else:
                ciphertext = decrypt_vertical(message, key, n)

        # Print with a | ("pipe" character) after it in case there are spaces at
        # the end of the encrypted message.
        print(ciphertext + '|')

        # Copy the encrypted string in ciphertext to the clipboard.
        pyperclip.copy(ciphertext)
        print()
        print("<Copied to clipboard>")


def convert_to_tuple(myPermutation): #function accepts input and converts the string into a tuple
    i = 0
    while i < len(myPermutation):
        s = ''
        while i < len(myPermutation) and myPermutation[i].isnumeric():
            s += myPermutation[i]
            i += 1
        try:
            del (myPermutation[i])
        except IndexError:
             #do nothing - code will fix itself later
             x = 1 #place an arbitrary statement to prevent indentation error
        for j in range(i-1, i - len(s), -1): #j in range (3, 1, -1)
            del(myPermutation[j])
            i -= 1
        if len(s) > 0:
            myPermutation[i - 1] = int(s)
            
    myPermutation = tuple(myPermutation)
    return myPermutation


def generatePermutations(lowerBound, higherBound):
    #if i generate from (1, 3) then I need the following
    #(1, 2, 3) (1, 2) (2, 1)
    #from (2, 4) I need the following
    #(1, 2), (2, 1), (1, 2, 3), (1, 3, 2), (3, 2, 1), (1, 2, 3, 4), (1, 3, 4, 2), (1, 2, 4, 3), ...
    #permutations(1, 2) + permutations(1, 3) + permutations(1, 4)
    permutation_list = []
    for i in range(lowerBound, higherBound + 1, 1):
        #in-built function imported from iter-tools
        permutation_list.append(list(permutations(range(1, i + 1))))
    total = []
    #merge sublists into one big list that has all the permutations
    for i in permutation_list:
        total += i
    return total


#returns the inverse of a permutation
#needed for decryption
def invert(perm):
    minValue = min(perm)
    li = []
    for l in range(minValue, len(perm) + minValue, 1):
        li.append(perm.index(l) + minValue)
    return tuple(li)


#additional parameter = n (for n-grams)
#precondition: permutation is valid with lowest column # = 1
def encrypt_horizontal(message, key, n=1, filler='X'):
    #example message: AABBCCDDEEFF
    #example permutation: 2, 1, 3
    #n = 2
    key = get_permutation(key) if type(key) == tuple else key_permutation(key)
    result = [] #represents the final message
    #1. break into 2-grams and add padding as necessary
    ngrams_list = break_into_ngrams_with_remainders(message, n)
    #add padding to the last ngram if it has been truncated -- if there is filler
    if filler != '':
        while len(ngrams_list[len(ngrams_list) - 1]) < n:
            ngrams_list[len(ngrams_list) - 1] += filler
    #2. make a list of horizontal parts ([['AA' 'BB' 'CC'] ['DD' 'EE' 'FF']])
    parts_to_tranpose_list = []
    index = 0
    while index < len(ngrams_list):
        li = []
        for j in range(len(key)):
            try:
                #if index is OK, append normally
                li.append(ngrams_list[index])
            except IndexError:
                #otherwise append a filler block
                li.append(filler * n)
            index += 1
        parts_to_tranpose_list.append(li)

    #3. transpose each part
    for part in parts_to_tranpose_list:
        for i in range(len(key)):
            result.append(part[key[i] - 1])

    return ''.join(result)

def decrypt_horizontal(message, key, n=1):
    #same as encrypting with the inverse permutation -- except if there are remainders
    key = get_permutation(key) if type(key) == tuple else key_permutation(key)
    inv_perm = invert(key)
    column_size = math.ceil(len(message) / (n * len(key)))
    are_remainders = len(message) / (n * len(key)) != column_size #check to see if there even are remainders
    #if there are no remainders, it is a simple calculation
    if not are_remainders:
        return encrypt_horizontal(message, inv_perm, n)
    #otherwise...
    grid_size = column_size * len(key)
    num_of_remainders = grid_size - math.ceil(len(message) / n)
    letters_per_row = n * len(key)
    truncated = ''.join(break_into_ngrams(message, letters_per_row))
    #this part of the message can be decrypted simply using the encryption algorithm & the inverse of the key
    non_remainder_decrypted = encrypt_horizontal(truncated, inv_perm, n)
    #but more needs to be done to get the remainder in the right order...
    non_truncated = break_into_ngrams_with_remainders(message, letters_per_row)
    remainder_portion = non_truncated[len(non_truncated) - 1]
    #if remainder is a single-cell remainder just append to the end of the message
    if len(remainder_portion) <= n:
        return non_remainder_decrypted + ''.join(remainder_portion)
    #otherwise... do the complicated rearrangement process
    else:
        reconstructed_rem_rows_list = []
        i = 0
        j = 0

        while i < len(key):

            addend = 0

            if key[i] == len(key) - num_of_remainders:

                block_remainder = (n - len(message) % n) % n
                addend = n - block_remainder

            elif key[i] in range(len(key) - num_of_remainders):

                addend = n

            reconstructed_rem_rows_list.append(remainder_portion[j: j + addend])
            j += addend
            i += 1

        #put the rows in the remainder list in the right order
        ordered_rem_rows = []

        for i in range(len(inv_perm)):
            ordered_rem_rows.append(reconstructed_rem_rows_list[inv_perm[i] - 1])
        #return the truncated decryption + the remainder decryption
        return non_remainder_decrypted + ''.join(ordered_rem_rows)

#precondition is same as encrypt_horizontal
def encrypt_vertical(message, key, n=1, filler='X'):
    # example message: AABBCCDDEE
    # example permutation: 2, 1, 3
    # n = 2
    key = get_permutation(key) if type(key) == tuple else key_permutation(key)
    result = []
    column_size = math.ceil(len(message)/(n * len(key)))
    #1. break into 2-grams and add padding as necessary
    ngrams_list = break_into_ngrams_with_remainders(message, n)
    # add padding to the last ngram if it has been truncated -- if filler is not the empty string
    if filler != '':
        while len(ngrams_list[len(ngrams_list) - 1]) < n:
            ngrams_list[len(ngrams_list) - 1] += filler
    #2. make a list of columns
    #[['AA' 'DD'] ['BB' 'EE'] ['CC']]
    columns_list = []
    for i in range(len(key)):
        columns_list.append(ngrams_list[i::len(key)])
    # add padding blocks to the columns that have been truncated
    #(in this case, add 'XX' to the 'CC' column)
    for column in columns_list:
        if len(column) < column_size:
            column.append(n * filler)
    #3. rearrange the columns in the list
    for j in range(len(key)):
        col = columns_list[key[j] - 1]
        result.append(''.join(col))

    return ''.join(result)


#this was EXTREMELY DIFFICULT to write and took a lot of thinking
#works for both complete AND incomplete columnar transposition
def decrypt_vertical(message, key, n=1):

    key = get_permutation(key) if type(key) == tuple else key_permutation(key)
    result = []
    column_size = math.ceil(len(message)/(n * len(key))) #helpful for reconstructing columns
    #ngrams_list = ngramFrequencyAnalysis.break_into_ngrams(message, n)
    #1. reconstruct columns
    reconstructed_columns_list = []
    grid_size = column_size * len(key)
    num_of_remainders = grid_size - math.ceil(len(message)/n)

    #1. RECONSTRUCT THE COLUMNS -- note they are still out of order
    i = 0
    j = 0
    while j < len(message):

        if key[i] in range(len(key) - num_of_remainders + 1):
            #if it is the very end-of-the-message reaching column
            if key[i] == len(key) - num_of_remainders:
                block_remainder = (n - len(message) % n) % n
                addend = n * column_size - block_remainder
            else:
                addend = n * column_size

            reconstructed_columns_list.append(message[j: j + addend])
            j += addend

        else:
            addend = n * (column_size - 1)
            reconstructed_columns_list.append(message[j: j + addend])
            j += addend

        i += 1

    #2. Put the columns back in order
    #make sure to use the inverse permutation!
    ordered_columns = []
    inv_perm = invert(key)

    for i in range(len(inv_perm)):
        ordered_columns.append(reconstructed_columns_list[inv_perm[i] - 1])

    #3. splice together the columns
    i = 0
    while i < (len(ordered_columns[0])):
        try:
            result.append(''.join(list(map(lambda x: x[i: i + n], ordered_columns))))
        except IndexError:
            #for every column
            for column in ordered_columns:
                if i < len(column):
                    #if it has extra characters past i, append the characters to the end of the message
                    result.append(column[i: len(column[i]) - 1])

        i += n

    return ''.join(result)

#returns the permutation of an ordering
#example: input is (0, 4, 2, 5)
#the output should be in order, [1-4]
#output: (1, 3, 2, 4)
#SPECIAL CASE example: input = (0, 1, 0, 2)
#output should be (1, 3, 2, 4)

def get_permutation(inp: tuple):

    indexes_list = []
    ordered = list(sorted(inp)) #sorted ordering (least to greatest)
    permutation_list = list(inp) #needs to be a list so it can be modified
    for item in ordered:
        index = permutation_list.index(item)
        indexes_list.append(index + 1) # add one to index because we are working in a base-1 indexing system
        permutation_list[index] = 'X' #change item at this index to indicate it has been added



    #turns out that inverting the indexes list returns the proper output. Wow!
    return invert(tuple(indexes_list))

#converts an alphabetical key to a permutation
#EXAMPLE: "PORK" --> (4, 2, 1, 3) because alphabetical order
def key_permutation(inp: str, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    #1. take out non-letters and spaces and convert to upper-case
    regex = re.compile('[^a-zA-Z]')
    inp = regex.sub('', inp).upper()
    nums = []
    #2. convert letters to numbers
    for letter in inp:
        nums.append(alphabet.index(letter))

    #3. get the appropriate permutation
    return invert(get_permutation(tuple(nums)))


def display_best_decryptions(message, direction, lowerBound, higherBound, n=1, num_of_decryptions=10, silentMode=False):
    decryptions = [] #this will be a list with tuples to store the key, message, and english score
    permutation_list = generatePermutations(lowerBound, higherBound)
    if direction == 'horizontal':
        decryptMessage = decrypt_horizontal
    else:
        decryptMessage = decrypt_vertical
    for perm in permutation_list:
        plaintext = decryptMessage(message, perm, n)
        decryptions.append((englishScore.english_word_score(plaintext), perm, plaintext))
    decryptions.sort(key=lambda x: x[0], reverse=True)

    if not silentMode:
        try:
            print("%d best solutions: " %num_of_decryptions)
            for i in range(num_of_decryptions):
                print("%-3d %-7.3f - %-40s: %s" %(i+1, decryptions[i][0], decryptions[i][1], decryptions[i][2]))
        except IndexError:
            pass
    return decryptions[0][2]


if __name__ == '__main__':
    main()
