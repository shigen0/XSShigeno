import requests
from colors import *

def send_request(session, base_url, parameter, value):
    """
    Sends a request to the specified URL with a given parameter and value.
    
    Args:
        session (requests.Session): The session object to use for sending the request.
        base_url (str): The base URL to which the parameter and value should be appended.
        parameter (str): The parameter name to be tested.
        value (str): The value to be assigned to the parameter in the request.
    
    Returns:
        int: The length of the response content from the server.
    
    This function sends a request using the provided session and captures the response.
    If the response status code is not 200, it prints an error message.
    """
    params = {parameter: value}
    response = session.get(base_url, params=params)

    if response.status_code != 200:
        print(f"{RED}[x] Unexpected status code for parameter {parameter}: {response.status_code}{RESET}")
    return len(response.content)


def param_searcher(base_url, nbr_params):
    """
    Searches for potentially vulnerable parameters in the given URL.
    
    Args:
        base_url (str): The base URL to test for vulnerable parameters.
        nbr_params (int): The number of parameters to test from the file.
    
    Returns:
        list: A list of parameters that showed different content lengths, suggesting potential vulnerabilities.
    
    This function iterates over a list of parameters from a file, testing each by
    sending a request and comparing the content length of the response to a baseline.
    Parameters causing a different response length are considered potentially vulnerable.
    """
    session = requests.Session()
    with open("params.txt", 'r') as file:
        base_size = send_request(session, base_url, "", "")
        vulnerable_parameters = []

        count_parameters_explored = 0

        for line in file:
            parameter = line.strip()

            size = send_request(session, base_url, parameter, "'")

            if size != base_size:
                print(f"{GREEN}[+] Parameter found : {parameter}{RESET}")
                vulnerable_parameters.append(parameter)

            count_parameters_explored +=1

            if count_parameters_explored == nbr_params:
                break

        return vulnerable_parameters
