import requests

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"


def send_request(session, base_url, parameter, value):
    params = {parameter: value}
    response = session.get(base_url, params=params)
    params = {parameter: value}
    response = requests.get(base_url, params=params)

    if response.status_code != 200:
        print(f"{RED}[x] Unexpected status code for parameter {parameter}: {response.status_code}{RESET}")
    return len(response.content)

def param_searcher(base_url, parameter_file, nbr_params):
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
