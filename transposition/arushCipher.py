from transposition.reverseEveryN import reverse
from miscellaneous.pyperclip import copy
#This is a custom transposition algorithm that I invented
#Note: EXTREMELY difficult to encode/decode by hand
#Only intended to be implemented in a programming setting

#############################################################
#SAMPLE ENCRYPTION #1
#
# P = 'hellothere'
#key = 2

#INITIAL SEPARATION:
# 1) hlohr (every 2nd letter starting from 1st)
# 2) eltee (every 2nd letter starting from 2nd)
#
# recur('hlohr') + recur('eltee')
#
#recur('hlohr') returns the following:
#
# 1. reverse: hlohr --> rholh
# 2. split, excluding first character (holh)
#    1) hl (every 2nd letter starting from 1st)
#    2) oh ((every 2nd letter starting from 2nd)
#
#    'r' + recur('hl') + recur('oh')
#    'r' + 'lh' + 'ho'

#recur('hlohr') = 'rlhho'

#repeat this for second half to get recur('eltee') = 'eleet'
#ciphertext: 'rlhhoeleet'
#
##############################################################################
#SAMPLE ENCRYPTION #2
#
#P = 'hellothere'
#key = 3
#
#INITIAL SEPARATION:
#  1) hlhe (every 3rd letter starting from 1st)
#  2) eoe (every 3rd letter starting from 2nd)
#  3) ltr (every 3rd letter starting from 3rd)
#
#  recur('hlhe') + recur('eoe') + recur('ltr')
#
#  recur('hlhe') returns the following:
#  1. reverse: hlhe --> ehlh
#  2. split, excluding first character (hlh)
#     1) h (every 3rd letter starting from 1st)
#     2) l (every 3rd letter starting from 2nd)
#     3) h (every 3rd letter starting from 3rd)
#
#     'e' + recur('h') + recur('l') + recur('h')
#     'e' + 'h' + 'l' + 'h'

#      recur('hlhe') = 'ehlh'

#repeat this for second part to get recur('eoe') = 'eoe'
#repeat this for third part to get recur('ltr') = 'rtl'
#ciphertext: 'ehlheoertl'



def encrypt(msg, key):
    res = ''
    #do the initial split (see sample encryptions above)
    for i in range(key):
        res += recur(msg[i::key], key)
    return res


def recur(part, key):
    #base case
    if not part:
        return ''

    part = reverse(part)
    truncated = part[1:]
    res = part[0]
    for i in range(key):
        res += recur(truncated[i::key], key)

    return res

#helper for decryption --> recur_list works on a list of indexes to determine positions of letters in a ciphertext
def recur_list(part, key):
    # base case
    if not part:
        return []

    part = list(reversed(part))
    truncated = part[1:]
    res = [part[0]] #must be a list, so it can be concatenated
    for i in range(key):
        res += recur_list(truncated[i::key], key)

    return res

#returns a list of indexes after encryptions -- used in decryption
def get_indexes_list(message_length, key):

    indexes_list = list(map(str, list(range(message_length)))) #this would be [0, 1, 2, ..., message_length]
    indexes_ordered = []
    for i in range(key):
        indexes_ordered += recur_list(indexes_list[i::key], key) #let recur_list function put them in order

    res = [int(i) for i in indexes_ordered]
    return res


def decrypt(msg, key):

    indexes = get_indexes_list(len(msg), key)
    res = [msg[indexes.index(i)] for i in range(len(msg))]
    return ''.join(res)


def main():
    message = input("Message: ")
    remove_spaces = input("Remove spaces <y/n>?: ")
    #inp validation
    while not remove_spaces.upper() in 'YN':
        remove_spaces = input("Remove spaces <y/n>?: ")

    if remove_spaces.upper() == 'Y':
        message = ''.join(message.split())

    mode = input("Encrypt/decrypt <e/d>: ")
    # inp validation
    while not mode.upper() in 'ED':
        mode = input("Encrypt/decrypt <e/d>: ")

    key = int(input("Key = "))

    if mode.upper() == 'E':
        p = encrypt(message, key)
    else:
        p = decrypt(message, key)

    print(p + '|')
    copy(p)
    print("<Copied to clipboard>")


if __name__ == '__main__':
    main()
