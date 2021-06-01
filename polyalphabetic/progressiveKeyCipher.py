from substitution import caesarCipher
import ast, re

#this alphabet is (usually) used -- it can be changed by changing this constant
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#to change the function that is being applied to determine the shift at the nth character, change the constant below
F_N = lambda n: n

#encryption with a variant of the progressive key cipher
#the shift applied to the nth character is determined by the function a_n
def encrypt(message, f_n = lambda x: x, alphabet=ALPHABET):
    result = []
    for i in range(len(message)):
        shift = f_n(i + 1)
        result.append(caesarCipher.encrypt(shift, message[i], alphabet))
    return ''.join(result)

#decryption is just the opposite -- use decrypt function in the caesarCipher file
def decrypt(message, f_n = lambda x: x, alphabet=ALPHABET):
    result = []
    for i in range(len(message)):
        shift = f_n(i + 1)
        result.append(caesarCipher.decrypt(shift, message[i], alphabet))
    return ''.join(result)

#Calculates the nth fibonnaci number using the doubling method, returns the tuple (F(n), F(n+1)).
#Taken from https://funloop.org/post/2017-04-14-computing-fibonacci-numbers.html
def fibonacci(n): 
    if n == 0:
        return (0, 1)
    else:
        a, b = fibonacci(n >> 1)
        c = a * ((b << 1) - a)
        d = a * a + b * b
        if n & 1:
            return (d, c + d)
        else:
            return (c, d)


def main():
    
    msg = input("Enter a message: ")
    nonletters = re.compile('[^a-zA-Z]')
    
    f_n = F_N
    
    #remove nonalphabetical chars from message & convert message to uppercase
    msg = re.sub(nonletters, '', msg).upper()
    
    mode = input("Encrypt/Decrypt <e/d>: ")
    if mode.upper() == 'E':
        print(encrypt(msg, f_n))
    else:
        print(decrypt(msg, f_n))

if __name__ == '__main__':
    main()
