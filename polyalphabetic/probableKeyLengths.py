from cryptanalysis import cipherStats
import statistics
import scipy.stats as st #make sure to add this in your project interpreter!
import re, math

nonletters = re.compile('[^A-Za-z]')

def get_confidence_interval(msg, period, confidence_level=95): #returns IOC 95% confidence interval
    iocs_list = [cipherStats.ioc(msg[i::period]) for i in range(period)]
    x_bar = statistics.mean(iocs_list)
    n = period
    t = st.t.ppf(1 - ((100 - confidence_level) / 2 / 100), n - 1)
    margin_of_error = t * (statistics.stdev(iocs_list)/(pow(n, 0.5)))
    return x_bar, margin_of_error


def get_probable_key_lengths(msg, max_period=26, confidence_level=99.995):
    #returns a list that contains tuples which display the probable key lengths, avg IOC, & margin of error
    #for each key length. Sorted by the average IOC (higher avg IOC = more probable)
    #First, take out all the nonletters and convert msg to uppercase
    msg = nonletters.sub('', msg).upper()
    probable_lengths_list = []
    for period in range(2, max_period + 1, 1):
           x_bar, margin_of_error = get_confidence_interval(msg, period)
           #append tuple: (period, mean IOC guess, margin of error)
           probable_lengths_list.append((period, x_bar, margin_of_error))

    probable_lengths_list.sort(key=lambda x: math.fabs(0.0667 - x[1]), reverse=False)

    return probable_lengths_list


def print_probable_key_lengths(msg, max_period=26, confidence_level=99.995):
    #prints the probable key lengths and average iocs, similar to DCode's printing format
    probable_lengths_list = get_probable_key_lengths(msg, max_period, confidence_level)
    for item in probable_lengths_list:
        print("L = %-3.2d Average IOC ~= %7.5f \u00B1 %.3f" %item)

    return ''

#returns the tuple for the length L that has the highest average IOC
def get_most_probable_key_length(msg, max_period=26):
    return get_probable_key_lengths(msg, max_period)[0]

if __name__ == '__main__':
    C = input("Enter a message: ")
    print_probable_key_lengths(C)

