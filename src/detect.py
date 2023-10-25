import time
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
import threading, concurrent.futures

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"

def check_vulnerable_parameter(parameters,payload,base_url):
    vuln_parameters = []
    for p in parameters:
        test_url = base_url + (f"?{p}={payload}")
        if check_xss(test_url):
            vuln_parameters.append(p)
    return vuln_parameters

def check_xss(url):
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)

    driver.get(url)
    try:
        WebDriverWait(driver, 1).until(EC.alert_is_present())
        driver.switch_to.alert.accept()
        return True
    except NoAlertPresentException:
        return False
    except TimeoutException:
        return False

def detect(base_url, parameters, payload):
    full_url = base_url + "?" + "&".join(f"{p}={payload}" for p in parameters)

    # Navigation and check for alert
    xss_detected = check_xss(full_url)

    if xss_detected:
        vulnerable_parameters = check_vulnerable_parameter(parameters,payload,base_url)
        print(GREEN + "[+] XSS Detected : " + payload + f"for parameter(s) : {vulnerable_parameters}" + RESET)
        return vulnerable_parameters,payload
    print(RED + "[x] No XSS detected for : " + payload + RESET)
    return ""
