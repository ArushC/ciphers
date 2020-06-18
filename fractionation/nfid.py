from transposition import swagmanCipher
from cryptanalysis.ngramFrequencyAnalysis import break_into_ngrams_with_remainders
from transposition.swagmanCipher import encrypt, decrypt

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
        print(nfid_encode(c, period, n))
    elif mode.upper() == 'D':
        print(nfid_decode(c, period, n))


if __name__ == '__main__':
   # main()
    c_list = [16, 12, 14, 0, 25, 44, 10, 9, 48, 40, 40, 32, 21, 3, 7, 3]
    res = []
    for num in c_list:
        res.append(bin(num)[2:].zfill(6))

    print(''.join(res))

    c = '010000001100000001100110100010011000101000100000010101000011000111010011001000101000111000001110'
















































