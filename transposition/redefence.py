from transposition.railfence import encryptMessage, decryptMessage, determineValues
from transposition.ngramTransposition import key_permutation, get_permutation, generatePermutations, \
invert, convert_to_tuple
from miscellaneous import pyperclip

#Notice that a lot of code that was used for the redefence cipher was copied from the  
#railfence cipher source code, and then modified slightly

def encrypt(msg, permutation, offset=0):
    # Each string in ciphertext represents a row in the grid.
    key = len(permutation)
    ciphertext = [''] * key
    index = 0
    row, step = determineValues(len(permutation), offset)  # starting row and positive/negative step depends on the offset
    # note that positive step = increasing row, negative step = decreasing row
    # for every character in the message
    while row < key and index < len(msg):
        ciphertext[row] += msg[index]  # add the character to the row it belongs in
        if (index > 0 and row == 0) or row == (key - 1):  # if the current char is one of the rails
            step *= -1  # change direction - if increasing, start decreasing, and vice versa
        row += step  # change the row (depending on whether the fence is going up or down)
        index += 1  # move to next character in message

    #finally, rearrange the rows
    return ''.join(rearrange_rows(ciphertext, permutation))


def decrypt(msg, permutation, offset=0):

    key = len(permutation)
    # step 5 in decryption: use the ciphertext chunks to put together the message with a process similar to encryption
    ciphertext_chunks = build_ciphertext_chunks(msg, permutation, offset)
    finalMessage = []
    row, step = determineValues(key, offset)
    index = 0
    while index < len(msg):
        finalMessage.append(ciphertext_chunks[row].pop(0))
        if (row == 0 and index > 0) or row == key - 1:
            step *= -1
        row += step
        index += 1

    return ''.join(finalMessage)


def build_ciphertext_chunks(msg, permutation, offset=0):
    #Step 1 in decryption: build array rowLengths to determine how many letters are in each row of the 'fence'
    key = len(permutation)
    rowLengths = [0] * key
    index = 0
    row, step = determineValues(key, offset)
    while row < key and index < len(msg):
        rowLengths[row] += 1
        if (index > 0 and row == 0) or row == (key - 1):
            step *= -1
        row += step
        index += 1

    #step 2: rearrange row lengths
    rowLengths = rearrange_rows(rowLengths, permutation)

    #step 3 in decryption: build ciphertext_chunks by placing the letters from each row of the 'fence' into its own list
    ciphertext_chunks = []
    for c in range(key):
        ciphertext_chunks.append([])
    index = 0 #same variable name used for another index
    for i in range(len(ciphertext_chunks)):
        for c in range(rowLengths[i]):
            ciphertext_chunks[i].append(msg[c + index])
        index += rowLengths[i]
    #step 4: put ciphertext chunks in the right order
    rearranged = rearrange_rows(ciphertext_chunks, invert(permutation))
    return rearranged
    #this array will be used in the final step of decryption


def rearrange_rows(rows: list, permutation: tuple):
    result = [rows[permutation[i] - 1] for i in range(len(rows))]
    return result


def main():
    message = input("Enter a message: ")
    remove = input("Remove spaces? [y/n]: ")
    if remove == 'y':
        message = message.replace(' ', '')

    raw_inp = input("Enter key: ")
    try:
        # if converting it to a tuple doesn't work
        key = get_permutation((convert_to_tuple(list(raw_inp))))
    except ValueError:
        # it must be a string key
        key = key_permutation(raw_inp)
        #
    offset = int(input("Enter offset: "))

    mode = input("Mode <encrypt/decrypt>?: ")

    if mode.upper() == 'ENCRYPT':
        ciphertext = encrypt(message, key, offset)
    else:
        ciphertext = decrypt(message, key, offset)

    # Print the encrypted string in ciphertext to the screen, with
    # a | ("pipe" character) after it in case there are spaces at
    # the end of the encrypted message.
    print(ciphertext + '|')
    print()
    pyperclip.copy(ciphertext)
    print("Result copied to clipboard")  


if __name__ == '__main__':
    main()
