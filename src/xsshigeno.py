# -*- coding: utf-8 -*-
import argparse
import concurrent.futures
import sys
from paramsearcher import *
from collections import defaultdict

from detect import *

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BOLD = "\033[1m"

def worker(vuln_url, params, payload, browser_manager):
    try:
        xss_detector = XSSDetector(browser_manager)
        return xss_detector.detect(vuln_url, params, payload)
    except Exception as e:
        print(f"Error occurred while processing payload {payload}: {e}")
        return None


def process_payloads(file, vuln_url, params, nbr_payloads, maxthreads, filtered_chars, browser_manager):
    counter = 0
    params_payloads_success = defaultdict(list)

    if maxthreads > 15:
        maxthreads = 15

    print(f"\n[*] Injecting in parameters {params}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=maxthreads) as executor:
        futures = {}
        for line in file:
            if counter >= nbr_payloads:
                break
            payload = line.strip()
            future = executor.submit(worker, vuln_url, params, payload, browser_manager)
            futures[future] = payload
            counter += 1 

        for future in concurrent.futures.as_completed(futures):
            payload = futures[future]
            try:
                result_tuple = future.result()
                if result_tuple:
                    vuln_params, result = result_tuple
                    if result:
                        params_payloads_success[tuple(vuln_params)].append(result)
            except Exception as e:
                print(f"Error occurred while processing payload {payload}: {e}")

    print_report(params_payloads_success, nbr_payloads)



def get_parameters(param, vuln_url, nbr_params):
    if param:
        return param.split(',')
    print("\n[*] No parameter specified, searching for parameters..." + RESET)
    return param_searcher(vuln_url, param, nbr_params)

def main(parameters, url, numberparams, file, numberpayloads, maxthreads, filtered_chars):
    browser_manager = BrowserManager(headless=True)
    params = get_parameters(parameters, url, numberparams)
    if not params:
        print(RED + "\n[x] No vulnerable parameters found." + RESET)
        sys.exit(1)

    print("[*] Opening payloads file...")

    with open(file, 'r') as file:
        process_payloads(file, url, params, numberpayloads, maxthreads, filtered_chars.split('*'), browser_manager)
    browser_manager.quit_browser()

def print_report(params_payloads_success, nbr_payloads):
    print("\n[*] Report")
    print(f"[*] Number of payloads processed: {nbr_payloads}")
    print(f"[*] Number of successful payloads: {sum(len(v) for v in params_payloads_success.values())}")
    print("[*] Successful payloads with its parameters:")
    for params, payloads in params_payloads_success.items():
        formatted_params = ", ".join(params)
        for payload in payloads:
            print(f"    Parameters: {formatted_params}")
            print(f"    Payload: {payload}\n")
    print("\n")


if __name__ == "__main__":
    print("""
__   __  _____   _____  _      _                            
\ \ / / / ____| / ____|| |    (_)                           
 \ V / | (___  | (___  | |__   _   __ _   ___  _ __    ___  
  > <   \___ \  \___ \ | '_ \ | | / _` | / _ \| '_ \  / _ \ 
 / . \  ____) | ____) || | | || || (_| ||  __/| | | || (_) |
/_/ \_\|_____/ |_____/ |_| |_||_| \__, | \___||_| |_| \___/ 
                                   __/ |                    
                                  |___/  
                                                     
by yaceno : https://yaceno.github.io/

    """)
    parser = argparse.ArgumentParser(description="An automated XSS detector.")
    parser.add_argument('-u', '--url', required=True, help='Vulnerable site')
    parser.add_argument('-p', '--parameters', default="", help='Parameters for testing XSS like "param1,param2,param3". It will search for parameters if not mentioned.')
    parser.add_argument('-n', '--numberpayloads', type=int, default=100, help='Number of payloads to inject. 100 payloads will be injected if not mentioned.')
    parser.add_argument('-f', '--filepayloads', default="payloads.txt", help='Payloads file. Uses the default one if not mentioned.')
    parser.add_argument('-m', '--numberparams', type=int, default=50, help='Number of parameters to search for if the -p option is not specified. All parameters will be searched for if not mentioned.')
    parser.add_argument('-t', '--maxthreads', type=int, default=1, help='Number of threads to search for parameters and payloads, max is set to 15, defaut to 1')
    parser.add_argument('-c', '--filtered-chars', default="", help='Filtered tokens, the payloads with these tokens won\'t be tested (e.g. -c "script*\'*alert"). Use * as the separator between characters.')

    args = parser.parse_args()
    main(args.parameters, args.url, args.numberparams, args.filepayloads, args.numberpayloads, args.maxthreads, args.filtered_chars)

