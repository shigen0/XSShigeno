from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
from colors import *
from collections import defaultdict
import concurrent.futures
import time
from itertools import islice

class XSSDetector:
    def create_driver(self):
        """
        Creates a headless Chrome WebDriver instance for browser automation.
        
        Returns:
            A Chrome WebDriver instance configured to run in headless mode.
        """
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        return webdriver.Chrome(options=options)

    def check_xss(self, url):
        driver = self.create_driver()
        try:
            # Inject the script to initialize the alert_called flag and override the alert function
            alert_script = """
            window.__alert_called = false;
            window.alert = function() {
                window.__alert_called = true;
            };
            """
            
            driver.execute_script(alert_script)
            driver.get(url)
            WebDriverWait(driver, 1).until(
                lambda d: d.execute_script('document.readyState') == 'complete'
            )
            if driver.execute_script("window.__alert_called;"):
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                    return True
                except NoAlertPresentException:
                    return False
            else:
                return False
        except TimeoutException:
            return False
        except Exception as e:
            print(f"Error occurred while checking XSS: {e}")
            return False
        finally:
            driver.quit()

    def find_vulnerable_parameters(self, parameters, payload, base_url):
        """
        Tests each parameter in a URL with a given payload to confirm which parameter is vulnerable to XSS.
        
        Args:
            parameters (list): A list of URL parameters to test.
            payload (str): The XSS payload to inject.
            base_url (str): The base URL without parameters.
        
        Returns:
            list: A list of parameters that are found to be vulnerable to XSS.
        """
        vuln_parameters = []
        for p in parameters:
            test_url = base_url + f"?{p}={payload}"
            if self.check_xss(test_url): 
                vuln_parameters.append(p)
        return vuln_parameters

    def detect(self, base_url, parameters, payload):
        """
        Detects XSS vulnerabilities for a given base URL, parameters, and payload.
        
        Args:
            base_url (str): The base URL to test.
            parameters (list): The parameters to inject the payload into.
            payload (str): The XSS payload to test with.
        
        Returns:
            tuple: A tuple containing the list of vulnerable parameters and the payload, if XSS is detected.
        """
        full_url = base_url + "?" + "&".join(f"{p}={payload}" for p in parameters)
        xss_detected = self.check_xss(full_url)
        if xss_detected:
            vulnerable_parameters = self.find_vulnerable_parameters(parameters, payload, base_url)
            # print("|" + GREEN + "[+] XSS Detected: " + payload + f" for parameter(s): {vulnerable_parameters}" + RESET)
            return vulnerable_parameters, payload
        # print("|" + RED + "[x] No XSS detected for: " + payload + RESET)
        return None

    def payload_detection_worker(self, vuln_url, params, payload):
        """
        A worker function for concurrent XSS detection tasks.
        
        Args:
            vuln_url (str): The base URL to test.
            params (list): The parameters to inject the payload into.
            payload (str): The XSS payload to test with.
        
        Returns:
            The result of the XSS detection attempt or None in case of error.
        """
        try:
            return self.detect(vuln_url, params, payload)
        except Exception as e:
            print(f"|"+RED+"[x] Error occurred while processing payload {payload}: {e}")
            return None

    def process_payloads(self, file, vuln_url, params, nbr_payloads, maxthreads, detected_filters):
        """
        Processes a list of payloads from a file to detect XSS vulnerabilities concurrently.
        
        Args:
            file (file object): A file object containing payloads to test.
            vuln_url (str): The base URL to test the payloads against.
            params (list): The parameters to inject the payloads into.
            nbr_payloads (int): The number of payloads to process from the file.
            maxthreads (int): The maximum number of threads to use for concurrent processing.
            detected_filters (list): A list of detected filters to exclude from testing.
        
        Returns:
            tuple: A tuple containing the results of the payload processing, number of payloads processed, and execution time.
        """
        counter = 0
        params_payloads_success = defaultdict(list)

        if maxthreads > 40:
            maxthreads = 40

        print(f"\n[*] Injecting in parameters {params}")

        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=maxthreads) as executor:
            futures = {}
            for line in islice(file, nbr_payloads):
                payload = line.strip()
                if payload in detected_filters:
                    continue
                else:
                    future = executor.submit(self.payload_detection_worker, vuln_url, params, payload)
                    futures[future] = payload
        
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

        execution_time = time.time() - start_time
        return params_payloads_success, nbr_payloads, execution_time
