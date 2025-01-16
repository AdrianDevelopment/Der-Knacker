import os
import hashlib
import platform
import re

VERSION = "1.2"

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
GRAY = "\033[37m"
ENDC = "\033[0m"

def display_banner():
    banner = (
        r"""
________                ____  __.                     __                 
\______ \   ___________|    |/ _| ____ _____    ____ |  | __ ___________ 
 |    |  \_/ __ \_  __ \      <  /    \\__  \ _/ ___\|  |/ // __ \_  __ \
 |    `   \  ___/|  | \/    |  \|   |  \/ __ \\  \___|    <\  ___/|  | \/
/_______  /\___  >__|  |____|__ \___|  (____  /\___  >__|_ \\___  >__|   
        \/     \/              \/    \/     \/     \/     \/    \/      
v"""
        + VERSION
        + """ / Adrian Lindstedt
"""
    )
    print(BLUE + banner + ENDC)
    print_c("Welcome to Der Knacker", BLUE)

def sha256_userinterface():
    algo = "SHA-256"
    hashinput = ""
    filepath = ""
    while True:
        temp = input(YELLOW + "derknacker>sha256> " + ENDC)
        tempfirst4 = temp[:4]
        tempover5 = temp[5:]
        if tempfirst4 == "hash":
            if tempover5 == "help":
                print("Enter your hash value after the keyword [hash ] with a space.")
                print("The hash value must have been created using the SHA256 algorithm.")
            else:
                algorithm = detect_hash(tempover5)
                if algorithm == algo:
                    hashinput = tempover5
                else:
                    print(RED + "🚫 Needed hash algorithm: " + algorithm + ENDC)
        elif tempfirst4 == "path":
            if tempover5 == "default":
                filepathtemp1 = __file__ #Pfad mit Dateinnamen
                filepathtemp2 = filepathtemp1[:-13]
                filepath = filepathtemp2 + "password-list-top-1000000.txt"
            elif tempover5 == "help":
                print("Enter a valid file path with the text document (ending: .txt) after the keyword [path ] with a space.")
                print("To use the supplied text document, enter [path default].")
                print("The supplied text document contains 1,000,000 common passwords.")
                print("Link to the creator of the list: https://github.com/danielmiessler/SecLists/tree/master.")
            elif os.path.isfile(tempover5):
                if not tempover5.lower().endswith('.txt'):
                    print_c("🚫 Please enter a textfile (ending: .txt)", RED)
                else:
                    filepath = tempover5
            else:
                print_c("🚫 Please enter a valid file path", RED)
        elif tempfirst4 == "word":
            if tempover5 == "help":
                print("Enter the word you want to convert into a hash value using the SHA256 algorithm after the keyword [word ] with a space.")
            elif tempover5 == "":
                print("Enter [word help] for support.")
            else:
                hashvalue = word_to_sha256(tempover5)
                print("Hash value:", hashvalue)
        elif temp == "input":
            if hashinput != "":
                print(GREEN + "Hash value: " + hashinput + ENDC)
            else:
                print_c("No file path entered.", RED)
            if filepath != "":
                print(GREEN + "File path: " + filepath + ENDC)
            else:
                print_c("No file path entered.", RED)
        elif temp == "run":
            if hashinput != "":
                if filepath != "":
                    hash_cracking(hashinput, filepath, algo)
                else:
                    print_c("🚫 Missing file path.", RED)
            else:
                print_c("🚫 Missing hash value.", RED)
        elif temp == "help":
            print("Enter [hash ] followed by the hash value you want to crack.")
            print("Enter [path ] followed by the file path where the word list is located.")
            print("Enter [path default] to use the supplied word list.")
            print("Enter [word ] followed by the word you want to convert into a hash value.")
            print("Enter [input] to see the current inputs.")
            print("Enter [run] to start the cracking.")
        elif temp == "back" or temp == "exit" or temp == "quit" or temp == "q":
            break
        else:
            print("Enter [help] for support.")
            
def md5_userinterface():
    algo = "MD5"
    hashinput = ""
    filepath = ""
    while True:
        temp = input(YELLOW + "derknacker>md5> " + ENDC)
        tempfirst4 = temp[:4]
        tempover5 = temp[5:]
        if tempfirst4 == "hash":
            if tempover5 == "help":
                print("Enter your hash value after the keyword [hash ] with a space.")
                print("The hash value must have been created using the MD5 algorithm.")
            else:
                algorithm = detect_hash(tempover5)
                if algorithm == algo:
                    hashinput = tempover5
                else:
                    print(RED + "🚫 Needed hash algorithm: " + algorithm + ENDC)
        elif tempfirst4 == "path":
            if tempover5 == "default":
                filepathtemp1 = __file__ #Pfad mit Dateinnamen
                filepathtemp2 = filepathtemp1[:-13]
                filepath = filepathtemp2 + "password-list-top-1000000.txt"
            elif tempover5 == "help":
                print("Enter a valid file path with the text document (ending: .txt) after the keyword [path ] with a space.")
                print("To use the supplied text document, enter [path default].")
                print("The supplied text document contains 1,000,000 common passwords.")
                print("Link to the creator of the list: https://github.com/danielmiessler/SecLists/tree/master.")
            elif os.path.isfile(tempover5):
                if not tempover5.lower().endswith('.txt'):
                    print_c("🚫 Please enter a textfile (ending: .txt)", RED)
                else:
                    filepath = tempover5
            else:
                print_c("🚫 Please enter a valid file path", RED)
        elif tempfirst4 == "word":
            if tempover5 == "help":
                print("Enter the word you want to convert into a hash value using the MD5 algorithm after the keyword [word ] with a space.")
            elif tempover5 == "":
                print("Enter [word help] for support.")
            else:
                hashvalue = word_to_md5(tempover5)
                print("Hash value:", hashvalue)
        elif temp == "input":
            if hashinput != "":
                print(GREEN + "Hash value: " + hashinput + ENDC)
            else:
                print_c("No hash value entered.", RED)
            if filepath != "":
                print(GREEN + "File path: " + filepath + ENDC)
            else:
                print_c("No file path entered.", RED)
        elif temp == "run":
            if hashinput != "":
                if filepath != "":
                    hash_cracking(hashinput, filepath, algo)
                else:
                    print_c("🚫 Missing file path.", RED)
            else:
                print_c("🚫 Missing hash value.", RED)
        elif temp == "help":
            print("Enter [hash ] followed by the hash value you want to crack.")
            print("Enter [path ] followed by the file path where the word list is located.")
            print("Enter [path default] to use the supplied word list.")
            print("Enter [word ] followed by the word you want to convert into a hash value.")
            print("Enter [input] to see the current inputs.")
            print("Enter [run] to start the cracking.")
        elif temp == "back" or temp == "exit" or temp == "quit" or temp == "q":
            break
        else:
            print("Enter [help] for support.")

def scan_userinterface():
    while True:
        temp = input(YELLOW + "derknacker>scan> " + ENDC)
        tempfirst4 = temp[:4]
        tempover5 = temp[5:]
        if tempfirst4 == "scan":
            if tempover5 == "":
                print("Enter [scan help] to get more detailed information.")
            elif tempover5 == "help":
                print("Enter the hash value you want to check after the keyword [scan ] with a space.")
                print("Supported algorithms: md5, sha1, sha256, sha512.")
                print("The information is without guarantee. Report incorrect results to Adrian Lindstedt.")
            else:
                algorithm = detect_hash(tempover5)
                if algorithm != "hash is unknown":
                    print(GREEN + "Algorithm used: " + algorithm + ENDC)
                    if algorithm == "SHA256":
                        temp1 = input(YELLOW + "You want to enter the console for " + algorithm + " [y, n]> " + ENDC)
                        if temp1 == "y":
                            sha256_userinterface()
                            break
                        elif temp1 == "help":
                            print("Enter [y] to enter the console for the", algorithm, "algorithm.")
                            print("The MD5 and SHA256 algorithms are currently implemented.")
                    elif algorithm == "MD5":
                        temp1 = input(YELLOW + "You want to enter the console for " + algorithm + " [y, n]> " + ENDC)
                        if temp1 == "y":
                            md5_userinterface()
                            break
                        elif temp1 == "help":
                            print("Enter [y] to enter the console for the", algorithm, "algorithm.")
                            print("The MD5 and SHA256 algorithms are currently implemented.")
                    else:
                        print_c("🚫 Algorithm not supported.", RED)
                else:
                    print_c("🚫 Algorithm is unknown.", RED)
        elif temp == "help":
            print("Enter [scan ] followed by the hash value where you want to find out the algorithm.")
        elif temp == "back" or temp == "exit" or temp == "quit" or temp == "q":
            break
        else:
            print("Enter [help] for support.")

def word_to_sha256(word):
    sha256_hash = hashlib.sha256(word.encode())
    return sha256_hash.hexdigest()

def word_to_md5(word):
    md5_hash = hashlib.md5(word.encode())
    return md5_hash.hexdigest()

def detect_hash(hash_value):
    hash_algorithms = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-224": hashlib.sha3_224,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-384": hashlib.sha3_384,
        "SHA3-512": hashlib.sha3_512,
        "Blake2b": hashlib.blake2b,
        "Blake2s": hashlib.blake2s
    }

    hash_patterns = {
        "MD5": r"^[a-f0-9]{32}$",
        "SHA-1": r"^[a-f0-9]{40}$",
        "SHA-224": r"^[a-f0-9]{56}$",
        "SHA-256": r"^[a-f0-9]{64}$",
        "SHA-384": r"^[a-f0-9]{96}$",
        "SHA-512": r"^[a-f0-9]{128}$",
        "SHA3-224": r"^[a-f0-9]{56}$",
        "SHA3-256": r"^[a-f0-9]{64}$",
        "SHA3-384": r"^[a-f0-9]{96}$",
        "SHA3-512": r"^[a-f0-9]{128}$",
        "Blake2b": r"^[a-f0-9]{128}$",
        "Blake2s": r"^[a-f0-9]{64}$"
    }

    for name, pattern in hash_patterns.items():
        if re.match(pattern, hash_value):
            return name
    
    return "hash is unknown"

def hash_cracking(hashinput, filepath, algo):
    found = False
    counter = 0
    if hashinput == "Exit 1" or filepath == "Exit 1":
        return
    with open(filepath, "r") as file:
        for line in file:
            word = line.strip()
            if algo == "SHA-256":
                hash_value = word_to_sha256(word)
            elif algo == "MD5":
                hash_value = word_to_md5(word)
            if hash_value == hashinput:
                print(GREEN + "🟢 Found the password: " + word + ENDC)
                found = True
                break
            counter += 1
            if counter % 100000 == 0:
                print("In row: ", counter)
        if found != True:
            print_c("❌ Password is not in list", RED)

def derknacker_userinterface():
    while True:
        temp = input(YELLOW + "derknacker> " + ENDC).strip()
        if temp == "help":
            print("Entering [sha256] starts the interface for the SHA256 algorithm.")
            print("Entering [md5] starts the interface for the MD5 algorithm.")
            print("Entering [scan] starts the interface for the algorithm scan.")
            print("Enter [exit; quit] to quit application.")
        elif temp == "exit" or temp == "quit" or temp == "q":
            print_c("Goodbye", BLUE)
            exit()
        elif temp == "sha256":
            sha256_userinterface()
        elif temp == "md5":
            md5_userinterface()
        elif temp == "scan":
            scan_userinterface()
        else:
            print("Enter [help] for support.")
            
def check_windows_version():
    system = platform.system()
    if system != 'Windows':
        print("This script is only for Windows.")
        exit()

    version = platform.version()
    
    if version.startswith("10.0"):
        build = int(version.split('.')[2])
        if build >= 22000:
            return
        else:
            print("You are using Windows 10.")
            print("This script does is not supported by Windows 10.")
            print("Switch to Windows 11 or use the terminal of your IDE.")
            temp = input("If you understand the risks and want to proceed, enter [yes]> ")
            if temp == "yes":
                return
            else:
                exit()
    else:
        print("You are using an unsupported version of Windows.")
        exit()
        
def print_c(text, color):
    print(color + text + ENDC)

def main():
    check_windows_version()
    display_banner()
    derknacker_userinterface()
    
if __name__ == "__main__":
    main()