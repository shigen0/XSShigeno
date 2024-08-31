import requests
from modules.colors import *

def analyzeFilters(base_url, params):
    """
    Analyzes the given URL for XSS filtering mechanisms by testing special characters.
    
    Args:
        base_url (str): The base URL to test for XSS vulnerabilities.
        params (list): A list of parameters to append the payloads to in the URL.
    
    Returns:
        list: A list of special characters that are not filtered, indicating potential XSS vulnerabilities.
    
    This function tests each special character by appending it to the base URL and
    comparing the occurrence of the character in the response to a baseline. Characters
    that appear less frequently than in the baseline are considered potentially filtered.
    """
    payload_test = "findme"
    test_url = base_url + "?" + "&".join(f"{p}={payload_test}" for p in params)
    
    session = requests.Session()
    response = session.get(test_url)
    
    occurrences_test = response.text.count("findme")

    special_chars = [
        '`', 
        '"', 
        '/*', 
        '//', 
        '/', 
        '*', 
        '-', 
        '+', 
        '!', 
        '@', 
        '#', 
        '$', 
        '%', 
        '^', 
        '&', 
        '(', ')', 
        '=', 
        '|', 
        '[', ']', 
        '{', '}', 
        ';', 
        ':', 
        ',', 
        '.', 
        '<', '>',
       '?'
       ]
    
    payloads = [f"{char}findme" for char in special_chars]

    filters = []

    print("[*] Analyzing XSS filters...")

    for index, payload in enumerate(payloads):
       full_url = base_url + "?" + "&".join(f"{p}={payload}" for p in params)
       response = session.get(full_url)
       if payload in response.text:
           occurrences_payload = response.text.count(payload)
           if occurrences_payload == occurrences_test:
               print("|"+ GREEN + f"[+] Payload not filtered: {payload}" + RESET)
               filters.append(special_chars[index])
           elif occurrences_payload < occurrences_test:
               print("|"+ GREEN + f"[+] Payload possibly filtered: {payload}" + RESET)
               filters.append(special_chars[index])
    if not filters:
        print("[+] No filters detected")

    return filters

       
       
