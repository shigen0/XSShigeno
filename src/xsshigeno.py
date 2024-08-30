# -*- coding: utf-8 -*-
import argparse
from modules.detect import *
from modules.analyzefilters import *
from modules.paramsearcher import *
from modules.colors import RED, GREEN, RESET
import sys

def get_parameters(param, vuln_url, nbr_params):
    """
    Extracts parameters to be tested for XSS vulnerabilities.
    
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

def main(parameters, url, numberparams, filepath, numberpayloads, maxthreads, detect_filters):
    """
    The main function of the XSS detection tool.
    
    Args:
        parameters (str): A comma-separated list of parameters to test.
        url (str): The URL of the site to test for XSS vulnerabilities.
        numberparams (int): The number of parameters to test if none are specified.
        filepath (str): Path to the file containing payloads to test.
        numberpayloads (int): The number of payloads to test.
        maxthreads (int): The number of concurrent threads to use for testing.
        detect_filters (bool): Flag indicating whether to perform filter detection.
    
    Orchestrates the overall process of detecting XSS vulnerabilities by parsing
    command-line arguments, searching for parameters if necessary, detecting any
    filtering mechanisms, and then processing payloads to find vulnerabilities.
    """
    params = get_parameters(parameters, url, numberparams)
    if not params:
        print(RED + "\n[x] No parameters found." + RESET)
        sys.exit(1)
      
    detected_filters = []
    if detect_filters:
        detected_filters = analyzeFilters(url,params)
    
    xss_detector = XSSDetector()  
    
    with open(filepath, 'r') as file:
        params_payloads_success, nbr_payloads, execution_time = xss_detector.process_payloads(file, url, params, numberpayloads, maxthreads, detected_filters)
        
    print_report(params_payloads_success, nbr_payloads, execution_time)

if __name__ == "__main__":
    print("""
__   __  _____   _____  _      _                            
\\ \\ / / / ____| / ____|| |    (_)                           
 \\ V / | (___  | (___  | |__   _   __ _   ___  _ __    ___  
  > <   \\___ \\  \\___ \\ | '_ \\ | | / _` | / _ \\| '_ \\  / _ \\ 
 / . \\  ____) | ____) || | | || || (_| ||  __/| | | || (_) |
/_/ \\_\\|_____/ |_____/ |_| |_||_| \\__, | \\___||_| |_| \\___/ 
                                   __/ |                    
                                  |___/  
                                                     
by yaceno : https://yaceno.github.io/

    """)
    parser = argparse.ArgumentParser(description="An automated XSS detector.")
    parser.add_argument('-u', '--url', required=True, help='Vulnerable site')
    parser.add_argument('-p', '--parameters', default="", help='Parameters for testing XSS like "param1,param2,param3". It will search for parameters if not mentioned.')
    parser.add_argument('-n', '--numberpayloads', type=int, default=100, help='Number of payloads to inject. 100 payloads will be injected if not mentioned.')
    parser.add_argument('-f', '--filepayloads', default="wordlists/payloads.txt", help='Payloads file. Uses the default one if not mentioned.')
    parser.add_argument('-m', '--numberparams', type=int, default=50, help='Number of parameters to search for if the -p option is not specified. All parameters will be searched for if not mentioned.')
    parser.add_argument('-t', '--maxthreads', type=int, default=1, help='Number of threads to search for parameters and payloads, max is set to 15, defaut to 1')
    # parser.add_argument('-c', '--filtered-chars', default="", help='Filtered tokens, the payloads with these tokens won\'t be tested (e.g. -c "script*\'*alert"). Use * as the separator between characters.')
    parser.add_argument('-fi', '--detectingfilters', action='store_true', help='Detect filters by analyzing the response with many payloads sent')

    args = parser.parse_args()
    main(args.parameters, args.url, args.numberparams, args.filepayloads, args.numberpayloads, args.maxthreads, args.detectingfilters)

