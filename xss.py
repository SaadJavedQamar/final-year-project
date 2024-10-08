import requests
from bs4 import BeautifulSoup
import logging
import time

# Set up logging to track vulnerabilities found
logging.basicConfig(
    filename='vulnbrace_dvwa_logs.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# URL and login credentials for DVWA
dvwa_url = "http://localhost/dvwa/"
login_url = dvwa_url + "login.php"
xss_url = dvwa_url + "vulnerabilities/xss_r/"
security_url = dvwa_url + "security.php"

# DVWA login credentials
payload = {
    "username": "admin",
    "password": "password",
    "Login": "Login"
}

# Start a session to maintain login state
session = requests.Session()

# Log into DVWA
def login_to_dvwa():
    start_time = time.time()
    
    response = session.get(dvwa_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Get the CSRF token from the login form
    csrf_token = soup.find("input", {"name": "user_token"})["value"]
    
    # Add CSRF token to the login payload
    payload["user_token"] = csrf_token
    
    # Perform login
    session.post(login_url, data=payload)
    login_time = time.time() - start_time
    logging.info(f"[*] Logged into DVWA in {login_time:.2f} seconds")
    print("[*] Logged into DVWA")

# Set security level to low
def set_security_level():
    response = session.get(security_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "user_token"})["value"]
    
    # Post the security level with CSRF token
    session.post(security_url, data={"security": "low", "seclev_submit": "Submit", "user_token": csrf_token})
    logging.info("[*] Security level set to low")
    print("[*] Security level set to low")

# XSS test with detailed logging and response debugging
def test_xss():
    xss_payload = "<script>alert('XSS')</script>"
    
    start_time = time.time()

    # Perform XSS by submitting the payload
    response = session.post(xss_url, data={"txtName": "Test", "mtxMessage": xss_payload, "btnSign": "Sign+Guestbook"})
    
    # Print full response for debugging purposes
    print("[DEBUG] Full Response:\n", response.text)  # Remove this in production
    
    # Parse the response using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Check if any <script> tag is present in the response
    script_tags = soup.find_all('script')

    if script_tags:
        detection_time = time.time() - start_time
        print("[+] XSS vulnerability detected! Script tag found in response.")
        logging.info(f"[+] XSS vulnerability detected using payload: {xss_payload}")
        logging.info(f"[+] Detection time: {detection_time:.2f} seconds")
        extract_xss_data(script_tags)
    else:
        print("[-] No XSS vulnerability detected.")
        logging.warning("[-] No XSS vulnerability detected.")

# Extract XSS reflected data
def extract_xss_data(script_tags):
    print("[*] Reflected XSS Payload:")
    logging.info("[*] Reflected XSS Payload:")
    for script in script_tags:
        print(script)
        logging.info(f"[*] {script}")

# Main workflow for XSS vulnerability testing
def run():
    start_time = time.time()
    
    login_to_dvwa()
    set_security_level()
    test_xss()
    
    total_time = time.time() - start_time
    logging.info(f"[*] Total execution time: {total_time:.2f} seconds")
    print(f"[*] Total execution time: {total_time:.2f} seconds")

# Execute the XSS test workflow
run()
