import numpy as np, re, math
from cryptanalysis.ngramFrequencyAnalysis import break_into_ngrams
from substitution.affineCipher import inv_mod, gcd

#using the Python numpy library for matrix operations
#description/tutorial can be found at https://www.programiz.com/python-programming/matrix

DEFAULT_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#precondition: key is a square numpy array that is invertible mod 26
def encrypt(msg: str, key, alphabet=DEFAULT_ALPHABET, padding='X'):

    matrix_size = len(key)
    plaintext = msg

    while len(plaintext) % matrix_size != 0:
        plaintext += 'X' #add padding to end of message

    partitioned_plaintext = break_into_ngrams(plaintext, matrix_size)

    res = []

    for i in range(len(partitioned_plaintext)):

        ngraph_numerical = []

        for j in range(matrix_size):
            ngraph_numerical.append(alphabet.find(partitioned_plaintext[i][j]))

        matrix_numerical = np.array(ngraph_numerical)
        ciphertext_numerical = key.dot(matrix_numerical)

        for k in range(matrix_size):
            res.append(alphabet[ciphertext_numerical[k] % len(alphabet)])

    return ''.join(res)


#same preconditions as encryption, w/ additional precondition that len(ciphertext) % matrix_size == 0
def decrypt(c: str, key, alphabet=DEFAULT_ALPHABET):

    determinant = round(np.linalg.det(key)) % len(alphabet)
    mod_mult_inverse = int(inv_mod(determinant, len(alphabet)))
    adj = adjugate(key)
    return encrypt(c, adj * mod_mult_inverse, alphabet)

#calculate a matrix minor (from https://stackoverflow.com/questions/3858213/numpy-routine-for-computing-matrix-minors)
def minor(arr,i,j):
    # ith row, jth column removed
    return arr[np.array(list(range(i))+list(range(i+1,arr.shape[0])))[:, np.newaxis],
               np.array(list(range(j))+list(range(j+1,arr.shape[1])))]

#precondition: matrix is square
def adjugate(matrix):

    matrix_size = len(matrix)
    res = np.zeros(shape=(matrix_size, matrix_size), dtype=int)

    for i in range(matrix_size):
        for j in range(matrix_size):
            minor_matrix = minor(matrix, i, j)
            m = (-1)**(i + j) * round(np.linalg.det(minor_matrix))
            res[i][j] = m

    return res.transpose()

#precondition: keyword length is square
def get_keyword_matrix(keyword, alphabet=DEFAULT_ALPHABET, mode='R'):

    matrix_size = round(math.sqrt(len(keyword)))
    res = np.zeros(shape=(matrix_size, matrix_size), dtype=int)

    for i in range(matrix_size):
        for j in range(matrix_size):
            k = i * matrix_size + j   #k = index in keyword. ex. (0, 0) --> 0, (0, 1) --> 1, (1, 0) --> 2, (1, 1) --> 3
            res[i][j] = alphabet.find(keyword[k])

    return res if mode == 'R' else res.transpose() #other mode = writing keyword vertically

def main():

    msg = input("Enter message: ")
    nonletters = re.compile('[^A-Za-z]')
    mode = input("Encrypt/decrypt <e/d>?: ")

    while not (mode.upper() in 'ED'):  # input validation
        mode = input("Encrypt/decrypt <e/d>?: ")

    keyword = input("Keyword = ")
    keyword = re.sub(nonletters, '', keyword).upper()

    #make sure keyword length is a perfect square and is invertible mod26
    matrix = get_keyword_matrix(keyword)

    while int(math.sqrt(len(keyword)) + 0.5) ** 2 != len(keyword) or gcd(round(np.linalg.det(matrix)) % 26, 26) != 1:
        print("Keyword length must be a perfect square and be invertible mod26.")
        keyword = input("Keyword = ")
        keyword = re.sub(nonletters, '', keyword).upper()

    if mode.upper() == 'E':
        print(encrypt(msg, matrix))
    else:
       print(decrypt(msg, matrix))


if __name__ == '__main__':
    main()
