from substitution import wordPatterns, substitutionCipher
import re, copy, time

#note: an arisocrat cipher is any substitution cipher with known word boundaries
#this program solves arisocrats, works best when word count >= 300 AND the majority
#of words in the ciphertext appear in the dictionary file that you are using
#check out the slideshow based on this program at tinyurl.com/ccslides31

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
nonletters_and_spaces = re.compile('[^A-Za-z\s]')

def get_blank_mapping():

    return {'A': [], 'B': [], 'C': [], 'D': [], 'E': [], 'F': [], 'G': [], 'H': [], 'I': [], 'J': [], 'K': [], 'L': [],
            'M': [], 'N': [], 'O': [], 'P': [], 'Q': [], 'R': [], 'S': [], 'T': [], 'U': [], 'V': [], 'W': [], 'X': [],
            'Y': [], 'Z': []}


#returns word pattern of a word as defined in the "Cracking Codes With Python" book (ex. APPLE --> "0.1.1.2.3")
def get_word_pattern(word):

    index = 0
    lw_dict = {}
    res = []

    for letter in word:
        if letter not in lw_dict:
            lw_dict[letter] = str(index)
            index += 1
        res.append(lw_dict[letter])

    return '.'.join(res)


#returns the mapping for an aristocrat cipher based on word patterns
def get_mapping(ciphertext):

    words = ciphertext.split()
    overall_mapping = get_blank_mapping()

    for word in words:

        word_pattern = get_word_pattern(word)

        try:
            possible_words = wordPatterns.allPatterns[word_pattern]
        except KeyError: #if this is not a word pattern that is found in the dictionary, skip to the next word
            continue

        this_mapping = get_blank_mapping()

        #iterate over every possible letter in every possible word to get the mapping for this individual word
        for possibility in possible_words:
            index = 0
            while index < len(possibility):
                if not (possibility[index] in this_mapping[word[index]]):
                    this_mapping[word[index]].append(possibility[index])
                index += 1

        #intersect this mapping with the overall mapping
        intersected_mapping = get_blank_mapping()
        for letter, possibilities in overall_mapping.items():
            if not possibilities:
                intersected_mapping[letter] = copy.deepcopy(this_mapping[letter])
            elif not this_mapping[letter]:
                intersected_mapping[letter] = copy.deepcopy(possibilities)
            else:
                for l in this_mapping[letter]:
                    if l in possibilities:
                        intersected_mapping[letter].append(l)

        overall_mapping = intersected_mapping
        #print(overall_mapping['B'])
    '''print()
    count = 0

    for (key, val) in overall_mapping.items():
        if (count % 4 == 0):
            if (count == 0): print('{ ', end='')
            else: print()
        count += 1
        print(key + ' : ' + str(val) + ', ', end='')

    print('}', end='')
    print()'''
    return overall_mapping

#returns the INVERSE key based on the mapping, and the character  wherever the letter cannot be determined
def get_key_from_mapping(overall_mapping, default_alphabet=ALPHABET):

    inv_key = [''] * 26
    looping = True

    while looping:

        looping = False

        for letter, possibilities in overall_mapping.items():
            if (len(possibilities) == 1):
                inv_key[default_alphabet.find(letter)] = possibilities[0] #finalized letters

        for item in inv_key:
            if not (item == ''):
                for possibility in overall_mapping.values():
                    if item in possibility and len(possibility) > 1:
                        possibility.remove(item)
                        looping = True #if successfully able to narrow down possibilites, loop through again

    return ''.join(inv_key)


#decrypts a substitution cipher in which word boundaries are known
def main(message):

    message = re.sub(nonletters_and_spaces, '', message).upper()
    start = time.time()
    mapping = get_mapping(message)
    inverse_key = get_key_from_mapping(mapping)
    substitutionCipher.encrypt(message, inverse_key)
    el = time.time() - start
    print("Time: " + str(el) + " seconds.")
    print()
    if not ('' in inverse_key):
        enc_key = substitutionCipher.invert(inverse_key)
        print("Encryption Alphabet: " + enc_key) #only print encryption alphabet if decryption was 100% successful
    print("Decryption Alphabet: " + inverse_key)
    print()
    print("Plaintext: " + substitutionCipher.encrypt(message, inverse_key))
    

if __name__ == '__main__':
    message = input("Enter a message: ")
    main(message)
