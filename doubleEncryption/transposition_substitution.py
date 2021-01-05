from transposition import railfence, boxCipher, reverseEveryN, ngramTransposition
from cryptanalysis.ngramFrequencyAnalysis import get_ngrams_with_frequencies, get_most_frequent_ngram_count
from fractionation import nfid
from substitution.manualSubDecoder import color
from transposition import horizontalVerticalCrack
from substitution import substitutionCrack
from transposition.manualTransDecoder import factors
from transposition import redefence
from miscellaneous import dictionaryAttack
import time
NGRAMS = 3 #This constant determines how possible results will be 'scored'
#in this case, the 'best' solution will have the highest max trigram count

best_entries = [] #a global list -- it will be assigned values in main
bruteforced = False

def main():

    msg = input("Enter a message: ")
    spaces = input("Remove spaces <y/n>?: ")
    while not spaces.upper() in 'YN': #input validation loop
        spaces = input("Remove spaces <y/n>?")

    if spaces.upper() == 'Y':
        msg = ''.join(msg.split())

    reversed_msg = False #boolean to use later

    while True:

        character = input("""
R) reverse message
H) try horizontal transposition
V) try vertical transposition
F) try railfence
D) try redefence
B) try box cipher
O) try box cipher with reversed blocks
N) try reverse every n
I) try nfid (transposition in blocks)
        \n""")
        print()  # padding
        # input validation
        while not character.upper() in 'RHVFDBONI':
            character = input("Please enter 'R', 'H', 'V', 'F', 'D', 'B', 'O', 'N', or 'I': ")

        if character.upper() == 'R':
            reversed_msg = not reversed_msg
            if not reversed_msg:  # if horizontal view
                print("Read the message " + color.BOLD + "LEFT TO RIGHT: " + color.END)
            else:  # otherwise if columns view
                print("Read the message " + color.BOLD + "RIGHT TO LEFT: " + color.END)

            print()
            msg = reverseEveryN.reverse(msg)
            print(msg)

        elif character.upper() == 'I':
            best_entries[:] = get_best_decryptions_nfid(msg)
            print_best_nfid(best_entries)

        elif character.upper() == 'F':
            best_entries[:] = get_best_decryptions_railfence(msg)
            print_best_railfence_entries(best_entries)

        elif character.upper() == 'D':
            best_entries[:] = get_best_decryptions_redefence(msg)
            print_best_redefence(best_entries)

        elif character.upper() in 'HV':

            n = input("Transpose the n-grams. n = ")
            while not (n.isnumeric() and (int(n) > 0 and int(n) < len(msg))):
                n = input("Transpose the n-grams. n = ")

            n = int(n)

            mode_hv = input("""
B) bruteforce
C) custom algorithm
D) dictionary attack

""")

            while not mode_hv.upper() in 'BCD':
                mode_hv = input("Please enter 'B', 'C', or 'D':")

            global bruteforced #this variable needs to be changed both inside and outside

            if mode_hv.upper() == 'B':
                bruteforced = True
                print()
                bruteforce = input("Bruteforce all permutations up to size 6? (default) <y/n>: ")
                while not bruteforce.upper() in 'YN':
                    bruteforce = input("Bruteforce all permutations up to size 6? (default) <y/n>: ")

                if bruteforce.upper() == 'Y':
                    best_entries[:] = get_best_decryptions_horizontal_vertical(msg, mode=character.upper(), n=n)
                else:
                    lower, upper = prompt_lower_upper_bound(msg)
                    best_entries[:] = get_best_decryptions_horizontal_vertical(msg,
                    mode=character.upper(), n=n, lower_bound=lower, upper_bound=upper)

                print()  # padding
                print_best_horizontal_vertical_entries(best_entries)

            else:

                #give information about factors of message kength (useful if not bruteforcing)
                print()
                print("The length of the message is %d. Probable key lengths are: " % len(msg), end='')
                print(*factors(len(msg)), sep=', ')
                print()

                global dictionary_attacked  # this variable needs to be changed both inside and outside

                if mode_hv.upper() == 'C':
                    key = input("Custom permutation iteration algorithm. Try with permutation size = ")
                    while not (key.isnumeric() and (int(key) > 1 and int(key) < len(msg))):
                        key = input("Please enter a valid permutation size: ")

                    key = int(key)
                    iterations = input("Number of iterations (100-200 recommended): ")
                    while not (iterations.isnumeric() and int(iterations) > 0):
                        iterations = input("Please enter a valid number of iterations: ")
                    print() #padding
                    iterations = int(iterations)
                    best_entries[:] = horizontalVerticalCrack.decrypt(ciphertext=msg, lowerBound=key, upperBound=key,
                                      num_of_times=iterations, n=n, direction=character.upper(),
                                      fitness_score=lambda x: get_most_frequent_ngram_count(x, n=NGRAMS))

                    horizontalVerticalCrack.print_best_solutions(best_entries)  # this is the scoring method)
                    print()

                else: #dictionary attack

                    dictionary_attacked = True

                    lower = input("Dictionary attack! Minimum word length = ")
                    while not (lower.isnumeric() and (int(lower) >= 1)):
                        lower = input("Please enter a valid minimum word length: ")
                    upper = input("Maximum word length = ")
                    while not (upper.isnumeric() and (int(upper) >= 1) and int(upper) >= int(lower)):
                        upper = input("Please enter a valid maximum word length: ")

                    best_entries[:] = dictionaryAttack.dict_attack(msg, 'c' if character.upper() == 'V' else 'h',
                            int(lower), int(upper), fitness=lambda x: get_most_frequent_ngram_count(x, n=NGRAMS))

                    dictionaryAttack.print_best_solutions(best_entries)

        elif character.upper() in 'BON':
            lowerBound, upperBound = prompt_lower_upper_bound(msg)
            print() #padding
            best_entries[:] = get_best_decryptions_other(msg=msg, mode=character.upper(), lowerBound=lowerBound,
            upperBound=upperBound)
            print_best_other(best_entries)

        if not character.upper() == 'R':
            attempt_substitution_break(best_entries, mode=character)
            print()
            print(msg)


#FUNCTIONS TO RETRIEVE SCORE LISTS FOR EACH CIPHER TYPE ----------------------------------------------------------------

#this is the brute-force version for horizontal-vertical: if upperBound <= 6, use this
#returns a list of the (10) best solutions
def get_best_decryptions_horizontal_vertical(msg, mode, n=1, num_of_decryptions=10, lower_bound=2, upper_bound=6):

    decrypt = ngramTransposition.decrypt_horizontal if mode.upper() == 'H' else ngramTransposition.decrypt_vertical
    entries = []
    permutation_list = ngramTransposition.generatePermutations(lower_bound, upper_bound) #bruteforce is up to size 6

    for perm in permutation_list:
        plaintext = decrypt(msg, perm, n)
        most_freq_ngram, most_freq_ngram_count = get_most_frequent_ngram_and_count(plaintext, n=NGRAMS) #trigrams
        entries.append((most_freq_ngram_count, most_freq_ngram, perm, plaintext))
    #sort based on most frequent trigram count
    entries.sort(key=lambda x: x[0], reverse=True)


    return retrieve_best_entries(entries, num_of_decryptions)



#this is used for railfence cipher
def get_best_decryptions_railfence(msg: str, num_of_decryptions=10):

    offsets = input("Try offsets? <y/n>: ")
    while not offsets.upper() in 'YN': #input validation
        offsets = input("Try offsets? <y/n>: ")
    if offsets.upper() == 'Y':
        offsets_upper_bound = lambda x: 2 * x - 2

    else:
        offsets_upper_bound = lambda x: 1

    lowerBound, upperBound = prompt_lower_upper_bound(msg)

    entries = []

    for key in range(lowerBound, upperBound + 1):
        for offset in range(offsets_upper_bound(key)):
            plaintext = railfence.decryptMessage(key, msg, offset)
            most_freq_ngram, most_freq_ngram_count = get_most_frequent_ngram_and_count(plaintext, n=NGRAMS)  # trigrams
            entries.append((most_freq_ngram_count, most_freq_ngram, key, offset, plaintext))

    print() #padding
    return retrieve_best_entries(entries, num_of_decryptions)

def get_best_decryptions_nfid(msg, num_of_decryptions=10):
    #this one only checks for the FACTORS of the message length -- it doesn't make sense if the numbers do not
    #go in evenly
    #in doing so, this also checks for all possible swagman ciphers in which the key is a factor of the message length
    entries = []
    possible_values = factors(len(msg))

    for n in possible_values:
        for period in possible_values:
            if (period * n) > len(msg):
                break #possible_values is sorted, so once period is too big, just break out of this iteration
            plaintext = nfid.nfid_decode(msg, period, n)
            most_freq_ngram, most_freq_ngram_count = get_most_frequent_ngram_and_count(plaintext, n=NGRAMS)  # trigrams
            entries.append((most_freq_ngram_count, most_freq_ngram, n, period, plaintext))

    return retrieve_best_entries(entries, num_of_decryptions)


#this is used for swagman, swagman with reversed blocks, and reverse every n
def get_best_decryptions_other(msg, lowerBound, upperBound, mode, number_of_decryptions=10):

    if mode in 'SO':
        reversed_blocks = True if mode.upper() == 'O' else False
        box = True
    else:
        box = False #this means that it is a reverse every n decryption

    entries = []
    for key in range(lowerBound, upperBound + 1):
        if box:
            plaintext = boxCipher.decrypt(key=key, message=msg, reversed_blocks=reversed_blocks)
        else:
            plaintext = reverseEveryN.decrypt(msg, key)

        most_freq_ngram, most_freq_ngram_count = get_most_frequent_ngram_and_count(plaintext, n=NGRAMS)  # trigrams
        entries.append((most_freq_ngram_count, most_freq_ngram, key, plaintext))

    return retrieve_best_entries(entries, number_of_decryptions)

def get_best_decryptions_redefence(msg, number_of_decryptions=10):

    permutations = ngramTransposition.generatePermutations(2, 6)
    entries = []
    for perm in permutations:
        key = len(perm)
        for offset in range(2 * key - 2):
            plaintext = redefence.decrypt(msg, perm, offset)
            most_freq_ngram, most_freq_ngram_count = get_most_frequent_ngram_and_count(plaintext, n=NGRAMS)
            entries.append((most_freq_ngram_count, most_freq_ngram, perm, offset, plaintext))

    return retrieve_best_entries(entries, number_of_decryptions)


def retrieve_best_entries(entries, number_of_decryptions):
    entries.sort(key=lambda x: x[0], reverse=True)
    if len(entries) > number_of_decryptions:
        return entries[:number_of_decryptions]
    else:
        return entries

#returns the most frequent ngram and its count
def get_most_frequent_ngram_and_count(msg, n, sliding=True):

    d = get_ngrams_with_frequencies(msg, n, sliding)
    most_freq_ngram = list(d.keys())[0]
    most_freq_ngram_count = list(d.values())[0]

    return most_freq_ngram, most_freq_ngram_count


#END RETRIEVING FUNCTIONS ----------------------------------------------------------------------------------------------
#START PRINTING FUNCTIONS ----------------------------------------------------------------------------------------------

def print_best_nfid(entries):
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%18s %15s %11s %20s %16s" + color.END) % ("Count: ", "Ngram: ", "N: ", "Period: ", "Message: "))
    for i in range(len(entries)):
        try:
            print("%-10d %-15d %-15s %-15d %-15d %-20s" % (i + 1, entries[i][0], entries[i][1],
                                                entries[i][2], entries[i][3], entries[i][4]))
        except IndexError:
            break

def print_best_railfence_entries(entries):
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print(
        (color.BOLD + "%18s %15s %15s %16s %16s" + color.END) % ("Count: ", "Ngram: ", "Rails: ",
                                                                 "Offset: ", "Message: "))
    for i in range(len(entries)):
        try:
            print("%-10d %-15d %-15s %-15d %-15d %-20s" % (i + 1, entries[i][0], entries[i][1],
                                                           entries[i][2], entries[i][3], entries[i][4]))
        except IndexError:
            break

def print_best_horizontal_vertical_entries(entries):
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print(
        (color.BOLD + "%18s %15s %21s %16s " + color.END) % ("Count: ", "Ngram: ", "Permutation: ",
                                                                 "Message: "))
    for i in range(len(entries)):
        try:
            print("%-10d %-15d %-15s %-20s %-20s" % (i + 1, entries[i][0], entries[i][1],
                                                           str(entries[i][2]), entries[i][3]))
        except IndexError:
            break


def print_best_other(entries):
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print(
        (color.BOLD + "%18s %15s %13s %19s " + color.END) % ("Count: ", "Ngram: ", "Key: ",
                                                                 "Message: "))
    for i in range(len(entries)):
        try:
            print("%-10d %-15d %-15s %-15d %-20s" % (i + 1, entries[i][0], entries[i][1],
                                                           entries[i][2], entries[i][3]))
        except IndexError:
            break

def print_best_redefence(entries):
    print(color.RED + color.BOLD + "10 BEST SOLUTIONS: " + color.END)
    print((color.BOLD + "%18s %15s %21s %18s %18s" + color.END) % ("Count: ", "Ngram: ", "Permutation: ", "Offset",
                                                                 "Message: "))
    for i in range(len(entries)):
        try:
            print("%-10d %-15d %-15s %-25s %-15d %-20s" % (i + 1, entries[i][0], entries[i][1],
                                                         str(entries[i][2]), entries[i][3], entries[i][4]))
        except IndexError:
            break



def prompt_lower_upper_bound(msg):
    lowerBound = input("Enter lower bound (MIN = 2): ")
    while not (lowerBound.isnumeric() and (int(lowerBound) >= 2 and int(lowerBound) <= len(msg))):  # input validation
        lowerBound = input("Enter a valid lower bound: ")

    lowerBound = int(lowerBound)

    upperBound = input("Enter upper bound (MAX = %d): " %len(msg))
    while not (upperBound.isnumeric() and ((int(upperBound) >= 2 and int(upperBound) <= len(msg)) and
                                           int(upperBound) >= lowerBound)):  # input validation
        upperBound = input("Enter a valid upper bound: ")

    upperBound = int(upperBound)

    return lowerBound, upperBound

def attempt_substitution_break(scores_list, mode):
    print()
    ask = input("Try to break any of these as a simple substitution cipher <y/n>?: ")
    while not ask.upper() in 'YN':
        ask = input("Try to break any of these as a simple substitution cipher <y/n>?: ")

    while ask.upper() != 'N':

        index = input("Enter decryption number: ")
        while not (index.isnumeric() and (int(index) > 0 and int(index) < len(scores_list))):
            index = input("Please enter a valid decryption number: ")

        index = int(index) - 1
        cipher = scores_list[index][len(scores_list[index]) - 1]
        substitutionCrack.main(cipher)
        time.sleep(4)
        #determine which printout to do in the loop based on global variables and function parameters
        #not the best way to do this but I was lazy
        print()
        if mode.upper() in 'BON':
            print_best_other(best_entries)
        elif mode.upper() == 'I':
            print_best_nfid(best_entries)
        elif mode.upper() == 'F':
            print_best_railfence_entries(best_entries)
        elif mode.upper() == 'D':
            print_best_redefence(best_entries)
        elif bruteforced:
            print_best_horizontal_vertical_entries(best_entries)
        elif dictionary_attacked:
            dictionaryAttack.print_best_solutions(best_entries)
        else: #custom algorithm
            horizontalVerticalCrack.print_best_solutions(best_entries)

        print()
        ask = input("Try to break any of these as a simple substitution cipher <y/n>?: ")



if __name__ == '__main__':
    main()


#ENCRYPTED NFID: RAVQLSKRYKQYWLFDFKAKZTIJDKIYFYFIVQGIKQLZLOEYQEIVIALQDDQIYKEKLIQKFDDVRKETYITIALKLTEAFVTIHVJDSKEKKKAGITMFDEQFAKTAVQFDVQJEGYAYLBMOGEOKFAYQAKAOTXTKEAITIMZKDEALKMTSRZYKDEAFKLLIASEEODQYYQLDAIQKIFQKKLETLIADQYKKKVKTJRQKENEQIDSZAQDGKZDYYSKGIDWKQEKAYQAAAQISMKKEYXIFWFDDKZIYDEYQIQASFDTZRRQAKDIMIEFZFLZEOAIIEFJDASQTQKYDNLAEFTZKVXLTENAYWKSQKNYKDKZDYTIKKABKTFAVTFEDYJAKEAILAIFALFDFITFZFYLOSTILKEXFQQAGBEFFQFRAJDDQTEOQJSYKEIAQKDDWJEEEYIEYKYQAFTISRQKRFFRILGEXQEXLEHXTIIYQEQBXFVKKZEVAMDYFKIIFTDLIEAKFFIJTRDFQRLSAFYKTLAYAJYDKLXKJKILKMLEIKFALQJMKJDIIRKDQRAYZKLJOIKYZFLQITKDLTYYKXIVYGYKXKLTIJBNDFFYYITAIFGRKSFTATGFYNKJAKQAIFYEFYJANLTFBSQGKKIYYLIAWVYGYKEFNRLKLEYJBIGFJDYSABQBTAYYYERAILKEKEEILNVAQLKDIXEEFEIVKKEEVAQBXFZIIIMDEDDYAKLMZFFDIZZFDQKRGEQQKVFFIVKFDKLRKYQIDWXAYYVTTSYQUKAFLIIOEDIYQKLKQVKLDIJKKKLRGKKLIJTFDKYKDWILYKDIILXXTYTLKLYZSIQQILNOIKKYKTJDQSELIGIZEELARYKZKNQRTFZXMAIOQTNEYLFIEXFKAOQTNFZLDDVXEIIJSDKLLYRGTIYKKDDYKXYVYQTLTKIYIKYLFDOINEQGEFINVRZLQIDKVEKWZFLFIA
#SUB ONLY:  RLYASKVKQQRYWFZLKTFAIDKJDFVKYQIFGYIIKLQQOELEIZYVIDYADKLQEQIKLFRIDKQDEKVTYATILETKAILFVVKTJEIDKHSKKTEAMQGFFIDAKQQTFJADEVVGYBEAMOYOKLGFAKXYATQOKATEAMEIZATKLIDKMZETYASKFRDKLSDLEQIEYAOYQIFLQQDKKAIKLIYEAKTDKLQKVRNKQETKQJEIDQZSDDZGYAKYSDEKWKGKAIQYQQKAIKASEAMYXFZIDIFDYWKDEQDYATQSZIFRRDEQIFAMZKIFLAFZIJEIDOEASKLQYATDEQNFTXNZLAKTYVEWKNKSYZQKDKDYTAFIBAKKVKTTFJAEAIDKLYEAIFTFDFAFZLIFYTELIXOLFSKQQEFAFRGFABQJDESDOYQQKTJEIDEADEQWEKJYIYTEQIYASKFRQFGKRERIXFLQEHIXXYLTQEIEQVEBKVXKAFZMDIDYILFFIKTEAIDKJFFTQFRRLYASKYATAFLJYXIDKLKJKLKMLFJEAMILKKQJDKAIDYIQZRRKLKLJYQOZIIFTKYIDYVLKYTXGYLBKTNXIDKJFFTGYARYIKIFSFGKTFJAYATNKQYJAEAIFNFYLTQIFGYBKYSKLIYEAGFWYNVKRLYGKJFLBJEIDYQYSBYATYBAERKEAEIIKLLENVKEADEQIFLXEIEQVEBKVXKAFZMDIDYIEAIDKLFZMDFZIDFZQKQFRQFGKIEVVKLQFRIDKDKYWXVYATQYTUYSKAIIFOYLEQIDKLKJKLKQDKVIKLKTRLFGIDKJKYIDKLIDYIWKLXTYXLZTKSYLIQNKQOYIIKLKTJEIDLZQIESGELKQAZRRKTYNFZINXOEMQYATLFFQIKTEANXOFZVILXJDESDIDKRYLGKLTKYIDDYTYVLKYTXQKIYOYLIIFNKDEQIZGNLEVQFRIDKLKWFVZIEFA
#RAILFENCE ONLY:
#RWDKILYVKKYAAMLQLVDSQXERLSTKTFIYQDIIQEQDALYLDLKYFFQTILYRVIZLKKXALLYXQJLZFZKDIQDLYFJFILVDKFTAFVKTAQGBFKEMKZKSYIKIKRIQYDYQYFDQRDFAAKFXWNYATJAFFTQEJEEDYYRFQHEVMIEIRYJXMFJKKKTYGLFTSGKYLQLYRYDQEKNKEEFMKFQQVLWVKIKKKKKILTINTEEKFILFFVDRDYKYEIIKAYRZKVIQYYIRVTLKSEDQVEGXTEDEDDOFIYQNEZKEQKMZKDFEIFELNNEKDFTAETIEKFQSJEJTFGLIIEZDTDRALIKJQARLFIXBJGFKNJYIKEKGIYAEEEXQADDZZFVQYYSIDJITJDKYLKKIGQNNTQOIIYITQODZRLFAQLDKYQZAQIKIITHAITVALYAIITRLALAELKJSAKIAAIWYIQKZOQQZVSKIKEYFLLSABDTAKEKKFXEBFYKKFSFDLEKIRJIDTKKYITTAFFSAVKESBALALVKIIMFREFKAYFIKVRKKWXYQLDSAYXAIXLDLYYXYKGFKESQKIYGOIDEDELAJKMFFEMKAKZLYFEYQKAKQQDYWAIEDYAZIZIDYELYYDBVALDZIFFAOKDEQSRXXQKAIIJQKAKKAKDZYIYYTDAKFAENGYGNJJBYELDFEXDADDQIRDTUOQLKLDLILSOKLEZTOYKNXSGKVTLNNQWIKKTAQFEEKQKDEKEDQFJDOOTOAKAKQEQKKDEKDGKKKSIDTSFMJIADATZKAKIKFFXLRFYQEWIAEIYTVKLFFTYTLJMLYQQZVKNIRIJYAFYKFYFBYTIKEIBVYEFIFKIKQTYEKDFIIYZKYIZIRKEQTAJEKTLYIFLVFZVFILLQTIGAYQTSIDTTZGAFQAETKQKDAOGQQYRLXFFAKIIOLXYAIBWLAIQKIZGDYLQGDTIQRMEDLKIEV|
#ENCRYPTED HORIZONTALLY WITH A KEY <= 6
#ASLYRQQVKKFZYWRFAKTLJDDKIYQVKFYIFGIQQKLIEIELOIDYVZKLADYIKEQQIDFRLEKQDKATTYVTKLEIFVILAJEKTVHSDKIEAKTKFFQGMKQDAIJATFQVGEVDAMBEYKLYOOKXFAGQOATYEAATKZAEIMIDKLTETMZKKFASYLSDKRQILEDOYYAELQIFQKADKQIYKLITDAKEKVLQKQENKRJEKQTZSDQIGYDZDSDKYAKGKWEQYAIKAIQKQEAASKFZYXMFDDIIDEWKYATDYQIFSZQEQRDRMZFAILAIFKJEZIFEADOIQYKLSEQTDAXNFTNKTLAZWKVEYYZKSNKDKDQFITAYKVAKBFJTTKIDEAAEALYKFDFTIZLAFFTEFYIOLIXLQQSKFFRFAEBQFAGSDDEJQKYQOIDJETEQADEJYEKWEQYTISKYAIFGRQFRIREKQEFLXXYIXHEITQLEBQVEKAVXKDIZMFLFYIDTEIKFKJIDAQFFTFYARLRATKYSJYFLAKLIDXLKJKKJELFMLKMIADKQJKYIIDARKZRQJYKLLIIOZQYITKFLKYVDGYTXYTNBKLKJIDXGYFTFIKRYAFGFSIJATFKNKATYAEYJQNFIFAQILTYBKGYFLISKYGFEAYVKYNWGKLYRBJFLJYQIDEYASBYAEYBTAEKERLLIKIKENVEQIDEAEILXFEBQVEKAVXKDIZMFEAYIDLFDKIFZMDZZQDFIRQQFKIEGKFLQVKVDKRIFWXKYDTQYAVYSTUYIFAIKEQYLOLKDKIKQKLJIKKVDRLKTLDKGIFIDKYJDYLIKLXWKILZYXTYLKSTKQQNIIKYIOJEKTLZQDLIGEESIAZKQLTYRKRINFZNMQOEXLFATYKTQIFXOANEILZVFESJDXKRIDDKLLGYIDKYTYVYTDTXKYLYOKIQIFLIYEQKDNNLZGIFRVQELKDKIZIFVWXXFAE|
#ENCRYPTED VERTICALLY WITH A KEY = 8
#KLJFQVQITKTKFTGOYEKTKELKDKIGKYSIDSQFIQFTSYKEAFLQFDEWERIXEKYETSJJEJQJTKKFITKFFLYKDTANIVFEMQKFWTFKDRKYXIIDEKXLALDTYKFGIZYRFVILYIQTLIEDAEGQEDSDODYQTZKGKMFDFAFETNEQFTDTIOFQQEJYGLLEZFDRAIKIAROIXXGFAJYBEKLYAIEXKDDZFVDYSLJIGDKTKKQQNMQODYIKODELFKFDQLZKFKEVHQQVOKAAZRQIAKRJDDIKFWTDKJKQANKAJYFTSRETEYKEHEVIKFYFLFKYKIVLKRGTAQSFYEYKLEEKYFFFLKQIIKKKITYYESRIATVDKYXIIFFLQTFYEDQKAIETIJBLTMIASAQILEQAKQAIQIFAOAXVZAKIFLXEBYDKIFFYVFLIFYXLMKRQYTNTIJYFYYVFQBIKLBMIFQEIVYYKVFIWZNLZKYEFXJRYLYKLKEAYAKIEAKDIFDAADAFOIKKLYKEKKSYKAYDYRMZADZWKITKFFLAJQAYAKQTBMFKRTDMLIKZDGIYSYALKARBSEKAEVIKIRVKAKEKKIKLKQTIAFQIFELDYYEVKASWIYKIDLELVKMKEMAKZMFEQKAVQDSAIXYARZISELKDBFLDYFFDKDISREQKDIJLAKLKDLIYYDAFAETYGLJBRLDIXDLDQKDTAQLLDLXSOJEZZYKZSGDTLQQWRQKDGOIEDYAJKFFYKAALYLYQLKQDYWQEDEZILDYTYYTVAIZIQAOIEQQXXQAIAQKYKADZYKYTFKFQNGINJYYEVFEZADKIRXUOLKLYILQKLLTOFNXKKVINNDIVZKIQYLRVTKSGQVYXTTEDIFITNEZEQAZKQEIELNKKDKAEAEKGSJQTFRIIXDTFALKJQILFLBJYKNIIKWGIAEEQQAIZZGQYYIDQTJDYLIIGRNTEIILTQIZRV|
#SWAGMAN KEY = 17
#RTIAEVGGAIDKVDQIZATWBYEFIILBIYKJYTGYTFIAFMZVTITYQZNISYIILFIDKKFYTDLKRZYDIFDKAELADYQKKAJDQXYAQWDELDIKQDRINQFKDTFDYAKKVTFBQKEANGQIFZENKAIBEAEVTSKKOGATIYYIXIDLYKLWKIZTIYNKAILLTJIEOMQIKYQFRIQKKIXQASHXEKLAZYRNFNQIEDFQTLFKQEIEDVKLSDQQYEDAKZIKQAKDRJNSVFOJDKIKAYKIILYKGVYKIYZFUKGLOSNAKLDKKKQEAIAMAEELEKAYDEFYKTLDEFXAIAMDIBIQYKSLEIQRYJIXYGXNRKEWVJOQTDKOTTYITYIWEITZTFFEQRXFDTLYFKKYBRBLQEKISKDTIEOXYYQFKDEIIKQYEYAYKSKKQDXQTDSSWQYZKAFITTIJKLYEVAQDKLKYILEOLTIVQFLKLHQOAAOEQDADIONKFFKDEFLMJFJQKNFAYYANEIFKAKJXKKMFGXZZQVELESTKMSYAJESEFEZDJAQOKGTDFLEZYXSESGTVBDRDIQKLLQQZKQGIRKIFTKFLEKQKEKEQAALKAFQYJKQIFJARIIFAKKYKKKQKIDYZKAYVLKNEYYZRKKJGIFITIWADMSADEZEQYREDTYMRDDGILJBEVLFYFKITTZAITILFWQYIATAFZRFDDKMYZKKYALFQIEIYQXIKYKKFIFAAXFGWOVDKJRTLKYEAFIVDIEDAADLKQGYAKLTTIIAKYREIFILLVJTNYLEDKZKXYIKSERLXYOVZFIKLAEKTKQLZKXTIQYADFFTTIQLRDKKLFFFEBREAMIVLKLYIKFJIYQLGDQFMVXKLQQSAFQFYVFKYRJEXVFRKKLKFJYAJKQFDEYELILDTFDDLFKYYDVQVYLSDKDIZSLAEILTGEQFEFLLQJYTALGEEIZFVAQKDILYQEDIR
#REVERSE EVERY N
#DIVYZIELEOQQLKIIYGFIQYKVFDJKDIAFTKLZFWYRQQKVKSAYLRAETKKSHKDIEJTKVVFLIAKTELITAYTVKEDQKDIRFLKIQEQLKDAYAZIEMAETAKOQTAYXKAFGLKOYOMAEBYGVVEDAJFTQQKADIFFGQMDTKAEYILKIAKKDQQLFIQYOAYEIQELDSLKDRFKSAYTEZMKDILKTAESAKIAKQQYQIAKGKWKEDSYKAYGZDDSZQDIEJQKTEQKNRVKQLKAEODIEJIZFALFIKZMAFIQEDRRFIZSQTAYDQEDKWYDFIDIZFXYMJFTTKVKKABIFATYDKDKQZYSKNKWEVYTKALZNXTFNQEDTAYQLKSDSEDJQBAFGRFAFEQQKSFLOXILETYFILZFAFDFTFIAEYLKDIAEAYXXIHEQLFXIRERKGFQRFKSAYIQETYIYJKEWQEDAEDIEJTKQQYOTAYKSAYLRRFQTFFJKDIAETKIFFLIYDIDMZFAKXVKBEVQEIEQTLIIZOQYJLKLKRRZQIYDIAKDJQKKLIMAEJFLMKLKJKLKDIXYJLFAKNTAYAJFTKGFSFIKIYRAYGTFFJKDIXNTKBLYGXTYKLVYDIYKTFQYDIEJBLFJKGYLRKVNYWFGAEYILKSYKBYGFIQTLYFNFIAEAJYQIDMZFAKXVKBEVQEIEXLFIQEDAEKVNELLKIIEAEKREABYTAYBSYQTAYVXWYKDKDIRFQLKVVEIKGFQRFQKQZFDIZFDMZFLKDIAEIYDYDILKDIYKJKDIGFLRTKLKIVKDQKLKJKLKDIQELYOFIIAKSYUTYYTKRRZAQKLEGSEIQZLDIEJTKLKIIYOQKNQILYSKTZLXYTXLKWIDIYKTLKGLYRKDIDSEDJXLIVZFOXNAETKIQFFLTAYQMEOXNIZFNAFEIZVFWKLKDIRFQVELNGZIQEDKNFIILYOYIKQXTYKLVYTYD
