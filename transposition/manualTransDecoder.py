from transposition import boxCipher, reverseEveryN, ngramTransposition
from cryptanalysis.ngramFrequencyAnalysis import break_into_ngrams_with_remainders, get_distinct_ngrams
from substitution.manualSubDecoder import color
import re, copy, sys, ast, math
import itertools
from miscellaneous import pyperclip

'''
GOAL:


Enter a message:

The length of the message is ____ characters. Probable key lengths are
<factors>

Enter grid key:

<show grid, horizontal mode>


S) switch two columns
I) invert grid
B) reverse each row
M) reverse the entire message
R) reset
Q) save and quit



S) -->
Enter 1st column number:
Enter 2nd column number:

I) --> horizontal <--> vertical

R --> are you sure? start over? etc.

'''

#returns a grid representation of the message: (a 2 dimensional list)
def get_grid(msg, key):
    return break_into_ngrams_with_remainders(msg, key)


def get_grid_key(grid):
    return len(grid[0])

#prints in grid format, with row labels
def print_grid(grid, column_nums): #key parameter not needed -- can be determined from the grid

    print_row_labels(column_nums)
    for row in grid:
        for i in range(len(row)):
            print("%-4s" % row[i], end='\n' if i == len(row) - 1 else '')

    if len(grid[len(grid) - 1]) != get_grid_key(grid): #if grid has remainders, print for padding
         print()

    print_row_labels(column_nums)
    print()


#prints row labels given the array of column numbers
def print_row_labels(column_nums):
    # add row labels (bold blue in color)
    print(color.BLUE + color.BOLD, end='')
    for i in range(len(column_nums)):
        print("%-4d" % (column_nums[i]), end='\n' if i == len(column_nums) - 1 else '')
    print(color.END, end='')


#returns an inverted grid
def invert_grid(grid, inverted): #rows --> columns... this is basically just a box cipher with key = grid key

    key = get_grid_key(grid)
    msg = boxCipher.encrypt(key, message = ''.join(grid), filler=' ') if inverted \
    else boxCipher.decrypt(key, message = ''.join(grid))
    return get_grid(msg, key)


#returns grid with columns at indexes c_1 and c_2 switched
def switch_columns(grid, c_1, c_2, column_nums):
    key = get_grid_key(grid)
    columns = get_columns_list(grid)
    #switch the two columns
    i_1, i_2 = column_nums.index(c_1), column_nums.index(c_2)
    columns[i_1], columns[i_2] = \
    columns[i_2], columns[i_1]
    #keep the information stored in column_nums (displayed in blue on each printout)
    column_nums[i_1], column_nums[i_2] = column_nums[i_2], column_nums[i_1]
    new_msg_grid = get_columns_list(columns)
    return new_msg_grid, column_nums


def get_columns_list(grid): #copied straight from ngramTransposition -- just changed variable names
    i = 0
    key = get_grid_key(grid)
    result = [''] * key
    while i < key:
        for row in grid:
            if i < len(row):
                result[i] += row[i]
            else:
                result[i] += ' '

        i += 1

    return result

#returns grid with all rows reversed
def reverse_rows(grid):
    return list(map(reverseEveryN.reverse, grid))

#returns entire grid reversed
def reverse(grid):
    return get_grid(reverseEveryN.reverse(''.join(grid)), get_grid_key(grid))

#returns the initialized grid for a columnar transposition
def get_columnar_grid(grid, columnar):
    key = len(grid)
    msg = ''.join(grid)
    new_grid = invert_grid(get_grid(msg, key), inverted=columnar)
    new_msg = ''.join(new_grid)
    new_key = get_grid_key(grid)
    return get_grid(new_msg, new_key)


def factors(n): #using a simple algorithm to get list of all distinct factors
    f = []
    for i in range(1, math.ceil(pow(n, 0.5)) + 1, 1): #O(sqrt(n))
        if n % i == 0 and i not in f:
            f.append(i)
            if int(n / i) not in f:
                f.append(int(n/i))

    f.sort()
    return f


def main(ciphertext: str):
    #check to see if ciphertext is a save list
    #if it is a save list, it MOST LIKELY WILL NOT APPEAR EXACTLY THE SAME due to order of operations if the
    #key does not go in evenly due to unknown order of operations (did it get inverted first or rows reversed first?)

    # declare booleans to use later
    inverted = False
    reversed_msg = False
    reversed_rows = False
    columnar = False

    try:
        parts = ast.literal_eval(ciphertext)
        #extract data from a saved list (if that is the input)
        ciphertext, key, column_nums = parts[0], parts[1], parts[2]
        grid = get_grid(ciphertext, key)
        #do the initial printout
        print()
        print_grid(grid, column_nums)

    except (SyntaxError, ValueError):

        remove_spaces = input("Remove spaces <y/n>?: ")
        # input validation
        while not remove_spaces.upper() in 'YN':
            remove_spaces = input("Remove spaces <y/n>?: ")
        if remove_spaces.upper() == 'Y':
            ciphertext = ''.join(ciphertext.split())

        ciphertext = ciphertext.upper()
        print()
            #show probable key lengths and prompt user to enter one
        length = len(ciphertext)
        print("The length of the message is %d." %length)
        print("Probable key lengths are: " , end='')
        print(*factors(length), sep=', ')
        print()
        key = input("Enter grid key: ")
        #input validation
        while not (key.isnumeric() and 0 < int(key) < len(ciphertext)):
            key = input("Please enter a valid grid key: ")

        key = int(key) #key str --> int. This is also the # of columns

        print() #padding
        print( "TRANSPOSITION MANUAL DECRYPTION, Key = %d" %key)
        print()
        grid = get_grid(ciphertext, key)
        column_nums = list(range(1, key + 1)) #1-based index, not 0-based
        print_grid(grid, column_nums)


    while True: #main loop

        character = input("""
S) switch two columns
C) change grid type (horizontal/vertical)
T) transpose/revert grid
R) reverse each row
M) reverse the entire message
K) change grid key
Q) save and quit\n""")
        #input validation
        while not character.upper() in 'SCTRMKQ':
            character = input("Please enter 'S', 'C', 'T', 'R', 'M', 'K', or 'Q': ")

        if character.upper() == 'S':
            c_1 = input("Enter 1st column number: ")
            #input validation
            while not (c_1.isnumeric() and 0 < int(c_1) < key + 1):
                c_1 = input("Please enter a valid column number: ")

            c_2 = input("Enter 2nd column number: ")
            #more input validation
            while not (c_2.isnumeric() and 0 < int(c_2) < key + 1):
                c_2 = input("Please enter a valid column number: ")

            grid, column_nums = switch_columns(grid, int(c_1), int(c_2), column_nums)
            print()
            print_grid(grid, column_nums)

        elif character.upper() == 'C':
            print()  # padding
            columnar = not columnar
            if not columnar:  # if horizontal grid
                print(color.BOLD + "HORIZONTAL TRANSPOSITION GRID " + color.END)
            else:  # otherwise if columnar grid
                print(color.BOLD + "COLUMNAR TRANSPOSITION GRID " + color.END)

            print()
            grid = get_columnar_grid(grid, columnar)
            print_grid(grid, column_nums)

        elif character.upper() == 'Q':
            print()  # padding
            print("Your message: ", end='')
            print(color.RED + color.BOLD +  ''.join(grid) + color.END)
            print("Encryption Key = " + color.BOLD +
            str(tuple(ngramTransposition.invert(column_nums))) + color.END, end='')
            print()# even more padding
            save_list = str([''.join(grid), key, column_nums])
            print("Enter this next time to resume <copied to clipboard>: " + save_list)
            pyperclip.copy(save_list)
            sys.exit(0)


        elif character.upper() == 'T':
            print() #padding
            inverted = not inverted
            if not inverted: #if horizontal view
                print("Read off the "  + color.BOLD + "ROWS: " + color.END)
            else: #otherwise if columns view
                print("Read off the " + color.BOLD + "COLUMNS: " + color.END)

            print()
            grid = invert_grid(grid, inverted)
            print_grid(grid, column_nums)

        elif character.upper() == 'R':
            print() #padding
            reversed_rows = not reversed_rows
            if not reversed_rows:  # if horizontal view
                print("Read every row " + color.BOLD + "LEFT TO RIGHT: " + color.END)
            else:  # otherwise if columns view
                print("Read every row " + color.BOLD + "RIGHT TO LEFT: " + color.END)

            print()
            grid = reverse_rows(grid)
            column_nums = list(reversed(column_nums))
            print_grid(grid, column_nums)

        elif character.upper() == 'M':
            print()  # padding
            reversed_msg = not reversed_msg
            if not reversed_msg:  # if horizontal view
                print("Read the message " + color.BOLD + "LEFT TO RIGHT: " + color.END)
            else:  # otherwise if columns view
                print("Read the message " + color.BOLD + "RIGHT TO LEFT: " + color.END)

            print()
            grid = reverse(grid)
            print_grid(grid, column_nums)


        elif character.upper() == 'K':
            print()
            are_you_sure = input("Are you sure you would like to change the grid key? "
                                 "This will erase all of your current progress <y/n>?: ")
            #input validation
            while not are_you_sure.upper() in 'YN':
                are_you_sure = input("Change grid key <y/n>?: ")

            if are_you_sure.upper() == 'N':
                print()
                continue

            else:
                print()  # padding
                #ask for the grid key
                length = len(ciphertext)
                print("Recall the length of the message is %d. Probable key lengths are: " % length)
                print(*factors(length), sep=', ')
                print()
                key = input("Enter a grid key: ")
                #more input validation
                while not (key.isnumeric() and 0 < int(key) < len(ciphertext)):
                   key = input("Please enter a valid grid key: ")

                key = int(key)
                #reinitalize grid and column_nums
                grid = get_grid(ciphertext, key)
                column_nums = list(range(1, key + 1, 1))
                #print the new initialized grid
                print_grid(grid, column_nums)


if __name__ == '__main__':
    ciphertext = input("Enter a message: ")
    main(ciphertext)
