from miscellaneous import pyperclip
from englishDetection import englishScore

def main():
    message = input("Enter a message: ")
    remove = input("Remove spaces? [y/n]: ")
    if remove == 'y':
        message = message.replace(" ", "")
    crack = input("Crack code <y/n>? ")
    if crack == 'y':
        lowerBound = int(input("Lower bound: "))
        higherBound = int(input("Higher bound: "))
        result = displayBestDecryptions(message, lowerBound, higherBound)
    else:
        mode = input("Mode <encrypt/decrypt>?: ")
        key = int(input("Enter key: "))
        offset = int(input("Offset?: "))
        if mode == 'encrypt':
            result = encryptMessage(key, message, offset)
        elif mode == 'decrypt':
            result = decryptMessage(key, message, offset)
        
        # Print the encrypted string w/ a | ("pipe" character) after it in case 
        # there are spaces at the end of the encrypted message.
        print(result + '|')
        pyperclip.copy(result)
        print()
        print("<Copied to clipboard>")
        

def determineValues(key, offset): #determine starting row value and whether increasing/decreasing based on offset
    modular_equivalent = 2 * key - 2
    offset %= modular_equivalent
    if offset > key - 1:
        step = -1
        row = modular_equivalent - offset
    else:
        step = 1
        row = offset
    return row, step

def encryptMessage(key, message, offset=0):
    # Each string in ciphertext represents a row in the grid.
    ciphertext = [''] * key
    index = 0
    row, step = determineValues(key, offset) #starting row and positive/negative step depends on the offset
                                             #note that positive step = increasing row, negative step = decreasing row
    #for every character in the message
    while row < key and index < len(message):
            ciphertext[row] += message[index] #add the character to the row it belongs in
            if (index > 0 and row == 0) or row == (key - 1): #if the current char is one of the rails
                step *= -1  #change direction - if increasing, start decreasing, and vice versa
            row += step #change the row (depending on whether the fence is going up or down)
            index += 1  #move to next character in message
    return ''.join(ciphertext)
    
def build_ciphertext_chunks(key, message, offset=0):
    #Step 1 in decryption: build array rowLengths to determine how many letters are in each row of the 'fence'
    rowLengths = [0] * key
    index = 0
    row, step = determineValues(key, offset)
    while row < key and index < len(message):
        rowLengths[row] += 1
        if (index > 0 and row == 0) or row == (key - 1):
            step *= -1
        row += step
        index += 1
    #step 2 in decryption: build ciphertext_chunks by placing the letters from each row of the 'fence' into its own list
    ciphertext_chunks = []
    for c in range(key):
        ciphertext_chunks.append([])
    index = 0 #same variable name used for another index
    for i in range(len(ciphertext_chunks)):
        for c in range(rowLengths[i]):
            ciphertext_chunks[i].append(message[c + index])
        index += rowLengths[i]
    return ciphertext_chunks #this array will be used in the final step of decryption

def decryptMessage(key, message, offset=0):
    #step 3 in decryption: use the ciphertext chunks to put together the whole message using a process similar to encryption
    ciphertext_chunks = build_ciphertext_chunks(key, message, offset)
    finalMessage = []
    row, step = determineValues(key, offset)
    index = 0
    while index < len(message):
        finalMessage.append(ciphertext_chunks[row].pop(0))
        if (row == 0 and index > 0) or row == key - 1:
            step *= -1
        row += step
        index += 1

    return ''.join(finalMessage)

def displayBestDecryptions(message, lowerBound, higherBound, num_of_decryptions=10, silentMode=False):
    decryptions = [] #this will be a list with tuples to store the key, message, and english score
    #precondition: numOfDecryptions < len(alphabet)
    for key in range(lowerBound, higherBound + 1):
        for offset in range(2 * key - 2):
            plaintext = decryptMessage(key, message, offset)
            decryptions.append((int(englishScore.english_word_score(plaintext)), key, offset, plaintext))
    decryptions.sort(key=lambda x: x[0], reverse=True)
    if not silentMode:
        print("%d best solutions: " %num_of_decryptions)


if __name__ == '__main__':
    main()
