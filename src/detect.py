import time
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
import threading
from concurrent.futures import as_completed

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"

class BrowserManager:
    def __init__(self, headless=True):
        self.options = Options()
        self.options.headless = True
        self.driver = self.start_browser()

    def start_browser(self):
        return webdriver.Chrome(options=self.options)

    def quit_browser(self):
        if self.driver:
            self.driver.quit()


class XSSDetector:
    def __init__(self, browser_manager):
        self.browser_manager = browser_manager

    def check_xss(self, driver, url):
        driver.get(url)
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())
            driver.switch_to.alert.accept()
            return True
        except NoAlertPresentException:
            return False
        except TimeoutException:
            return False

    def check_vulnerable_parameter(self, driver, parameters,payload,base_url):
        vuln_parameters = []
        for p in parameters:
            test_url = base_url + (f"?{p}={payload}")
            if self.check_xss(driver,test_url):
                vuln_parameters.append(p)
        return vuln_parameters

    def detect(self, base_url, parameters, payload):
        options = Options()
        options.headless = True
        driver = webdriver.Chrome(options=options)    


        full_url = base_url + "?" + "&".join(f"{p}={payload}" for p in parameters)

        # Navigation and check for alert
        xss_detected = self.check_xss(driver, full_url)
        if xss_detected:
            vulnerable_parameters = self.check_vulnerable_parameter(driver, parameters,payload,base_url)
            print(GREEN + "[+] XSS Detected : " + payload + f"for parameter(s) : {vulnerable_parameters}" + RESET)
            driver.quit()
            return vulnerable_parameters,payload
        print(RED + "[x] No XSS detected for : " + payload + RESET)
        driver.quit()
        return None
