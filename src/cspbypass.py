import requests

RED = "\033[31m"
GREEN = "\033[32m"

def csp_bypass(target_url, params):
    # Prepare the URL with given parameters and value 'a'
    params_dict = {param: 'a' for param in params}
    response = requests.get(target_url, params=params_dict, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })

    # Check the Content-Security-Policy header
    csp = response.headers.get('Content-Security-Policy')
    if not csp:
        print(RED + "\n[x] No Content-Security-Policy header found.")
    else:
        print(GREEN + "\n[+] Content-Security-Policy found : \n\n" + csp + "\n\n")
