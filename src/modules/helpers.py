from modules.paramsearcher import *
from modules.colors import RED, GREEN, RESET

def get_parameters(param, vuln_url, nbr_params):
    """
    Extracts GET parameters to be tested for XSS vulnerabilities.
    
    Args:
        param (str): A comma-separated string of parameters, if already known.
        vuln_url (str): The base URL where parameters will be tested.
        nbr_params (int): Number of parameters to search for if none are specified.
    
    Returns:
        list: A list of parameters to be tested.
    
    If no parameters are specified, this function attempts to discover parameters
    by analyzing the given URL. If parameters are provided, it simply splits the string
    into a list based on commas.
    """
    if param:
        return param.split(',')
    print("\n[*] No parameter specified, searching for parameters..." + RESET)
    return param_searcher(vuln_url, nbr_params)

def print_report(params_payloads_success, nbr_payloads, time):
    """
    Prints a summary report of the XSS detection process.
    
    Args:
        params_payloads_success (dict): A dictionary where keys are parameter tuples and values are lists of payloads that succeeded.
        nbr_payloads (int): The total number of payloads processed.
        time (float): The total execution time of the payload processing.
    
    This function formats and prints out a detailed report including the execution time,
    number of payloads processed, and which parameters were found to be vulnerable along 
    with the successful payloads.
    """
    print("\n[*] Report")
    print(f"[*] Execution time : {round(time,1)} seconds")
    print(f"[*] Number of payloads processed: {nbr_payloads}")
    for params, payloads in params_payloads_success.items():
        formatted_params = ", ".join(params)
        for payload in payloads:
            print(GREEN + f"    Parameters: {formatted_params}" + RESET)
            print(f"    Payload: {payload}\n")
    print("\n")