from cryptanalysis.ngramFrequencyAnalysis import break_into_ngrams_with_remainders
from transposition.boxCipher import encrypt, decrypt
from miscellaneous import pyperclip
#n = # of characters that represent one letter
#this is encryption in blocks
#the blocks are equal to period * n
#apply a horizontal/vertical on each block, key = n
def nfid_encode(c, period, n):

    m = int(period * n)
    c_list = break_into_ngrams_with_remainders(c, m)
    result = []
    for i in range(len(c_list)):
        result.append(encrypt(key=n, message=c_list[i]))

    return ''.join(result)

#nfid decode is exactly the same --> the only difference is decode instead of encode
def nfid_decode(c, period, n):


    m = int(period * n)
    c_list = break_into_ngrams_with_remainders(c, m)
    result = []
    for i in range(len(c_list)):
        result.append(decrypt(key=n, message=c_list[i]))

    return ''.join(result)


def main():
    c = input("Enter a message: ")
    remove_spaces = input("Remove spaces <y/n>?: ")
    if remove_spaces.upper() == 'Y':
        c = ''.join(c.split())
    n = int(input("n = "))
    period = int(input("period = "))
    mode = input("Encrypt/Decrypt (e/d)?: ")
    if mode.upper() == 'E':
        res = nfid_encode(c, period, n)
    elif mode.upper() == 'D':
        res = nfid_decode(c, period, n)

    # Print with a | ("pipe" character) after it in case
    # there are spaces at the end of the decrypted message.
    print(res + "|")
    print()
    pyperclip.copy(res)
    print("<Copied to clipboard>")
    print("Warning: do not copy this manually because there is a pipe character at the end of the message that"
          " will mess up decryption.")

if __name__ == '__main__':
   main()
