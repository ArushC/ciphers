#This program is based on https://bionsgadgets.appspot.com/gadget_forms/acarefstats.html
#the statistics are all coded here
from cryptanalysis.ngramFrequencyAnalysis import get_ngrams_with_frequencies, break_into_ngrams
import re

nonletters = re.compile('[^A-Za-z]')

#index of coincidence - learn more about this statistic at https://www.dcode.fr/index-coincidence
def ioc(msg):
    #n=1 because ioc looks at individual letters (1-grams)
    appearances_dict = get_ngrams_with_frequencies(msg, n=1)
    N = len(msg)
    if N <= 1:
        return 0.0
    sum = 0
    for letter in appearances_dict.keys():
        n = appearances_dict[letter]
        sum += (n * (n-1))/(N * (N - 1))

    return sum


#max index of coincidence (periods 1 - 15)
#calculate ioc for a given period P by taking every P-gram, calculating its IOC, and averaging them
def mic(msg):
    max_ioc = 0
    for period in range(1, 16, 1):
        ngrams = break_into_ngrams(msg, period)
        ioc_list = [ioc(ngrams[i]) for i in range(len(ngrams))]
        if len(str(ioc_list[len(ioc_list) - 1])) != period: #if last item has a remainder
            del ioc_list[len(ioc_list) - 1] #delete it
        try:
            avg_ioc = sum(ioc_list)/len(ioc_list)
        except ZeroDivisionError:
            return "N/A"
        if avg_ioc > max_ioc:
            max_ioc = avg_ioc

    return max_ioc


#maximum kappa value (periods 1 - 15)
#ALPHABET = [A-Z] regardless of the message
#calculate kappa value for a given period P by shifting the cipher to the right P spaces
#then seeing what percentage of symbols coincide with those in the unshifted cipher
def mka(msg):
    kappa_values = []
    #for each period
    for period in range(1, 16, 1):
        #example: period = 1
        #unshifted: A|BCDEDFDA*
        #shifted:   *ABCDEDFD|A
        unshifted = msg[:len(msg) - period]
        shifted = msg[period:]
        count = 0
        for i in range(len(shifted)):
            if shifted[i] == unshifted[i]:
                count += 1
        #calculate kappa and add to a list of kappa vales
        try:
            kappa = count/(len(unshifted) - period)
        except ZeroDivisionError:
            return "N/A"
        kappa_values.append(kappa)

    return max(*kappa_values)


#DIC = digraphic index of coincidence
#Note: works in a SLIDING WINDOW
def dic(msg):
    appearances_dict = get_ngrams_with_frequencies(msg, n=2, sliding=True)
    N = len(msg) - 1
    if N <= 2:
        return 0.0
    sum = 0
    for letter in appearances_dict.keys():
        n = appearances_dict[letter]
        sum += (n * (n - 1)) / (N * (N - 1))

    return sum


#EDI = digraphic index of coincidence in a BLOCK WINDOW
def edi(msg):
    appearances_dict = get_ngrams_with_frequencies(msg, n=2, sliding=False)
    N = len(msg)/2
    if N <= 1:
        return 0.0
    sum = 0
    for letter in appearances_dict.keys():
        n = appearances_dict[letter]
        sum += (n * (n - 1)) / (N * (N - 1))

    return sum


#helper function to determine rod and lr
def rod_and_lr_helper(msg):
    #for every character c in the message
    #for every character d to the right of c
    #n = # of characters for which strings starting at c and d are identical
    #if n > 1, sum_all += 1
    #   if c & d are also an odd number of characters apart, increment sum_odd
    #if n = 3, increment r3
    r3 = 0
    sum_all = 0
    sum_odd = 0
    for index in range(len(msg)): #for every c in the message
        start_c_index = index
        for start_d_index in range(index + 1, len(msg), 1):
            n = 0
            try:
                while msg[start_c_index + n] == msg[start_d_index + n]:
                    n += 1
            except IndexError:
                pass
            if n > 1:
                if n == 3:
                    r3 += 1
                if (start_d_index - start_c_index)  % 2 == 1:
                    sum_odd += 1

                sum_all += 1

    return r3, sum_odd, sum_all


#ROD = the percentage of odd spaced repeats
def rod(msg):
    r3, sum_odd, sum_all = rod_and_lr_helper(msg)
    rod = sum_odd/sum_all
    return rod


#LR = the square root of the percentage of 3-character repeats
def lr(msg):
    r3, sum_odd, sum_all = rod_and_lr_helper(msg)
    lr = pow(r3, 0.5) / len(msg)
    return lr



if __name__ == '__main__':
    msg = input("Enter a message: ")
    msg = re.sub(nonletters, '', msg).upper()
    print("IOC: %8.3f" %(ioc(msg) * 1000))
    print("MIC: %8.3f" %(mic(msg) * 1000) if type(mic(msg)) == float else "MIC: %8s" %mic(msg))
    print("MKA: %8.3f" %(mka(msg) * 1000) if type(mka(msg)) == float else "MKA: %8s" %mka(msg))
    print("DIC: %8.3f" %(dic(msg) * 10000))
    print("EDI: %8.3f" %(edi(msg) * 10000))
    print("LR:  %8.3f" %(lr(msg) * 1000))
    print("ROD: %8.3f" %(rod(msg) * 100))
    print("See https://bionsgadgets.appspot.com/gadget_forms/acarefstats.html to compare these statistics"
          " to known cipher types")
