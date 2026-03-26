#===========================#
# I M P O R T S             #
#===========================#

import warnings
warnings.filterwarnings("ignore")

import os
import pyfiglet
import requests
import sys

sys.path.append("Apache")

import CVE_2021_41773

#===========================#
# C O L O R S               #
#===========================#

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    BACKGROUND_MAGENTA = '\033[105m'
    BACKGROUND_WHITE = '\033[47m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    ORANGE = '\033[38;5;208m'

os.system("color") # Remove this line if you're running this on Linux

#===========================#

if __name__ == "__main__":
    
    #===========================#
    # Banner and art.
    #===========================#
    
    print("")
    print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")
    ascii_banner = pyfiglet.figlet_format("  MACHETE", font="drpepper")
    print(f"{bcolors.WARNING}" + ascii_banner + f"{bcolors.ENDC}",end="")
    print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")

    #===========================#
    # User input.
    #===========================#

    print(f"{bcolors.OKCYAN}=" * 75 + f"{bcolors.ENDC}")
    print(f"| 🎯 {bcolors.WARNING}Target Input{bcolors.ENDC}")
    print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")
    
    # Target input.
    while True:
        domain = input(f"| Enter a [{bcolors.OKGREEN}URL{bcolors.ENDC}] to test: {bcolors.OKGREEN}")
        print(f"{bcolors.ENDC}",end="")
        print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")
        
        # If no domain was entered, exit.
        if (domain == "" or domain == " "):
        
            print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}");
            print(f"| No domain entered. Press any key to exit.")
            print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}");

            end = input("")
            sys.exit()
        
        # Sanitize the input.
        domain = domain.strip().lower()
        
        # If it's missing http:// or https://, add it in by default.
        if "http://" not in domain and "https://" not in domain: domain = "https://" + domain
        
        #===========================#
        
        # Apache
        CVE_2021_41773.exploit(domain, False)

        #===========================#
        
        print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")