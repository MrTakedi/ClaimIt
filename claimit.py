import requests
import xml.etree.ElementTree as ET
import re
import getpass
import socket
import sys
from datetime import datetime

# Global variables
LOGFILE = "claim_plex_server.log"

# Function to log messages
def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOGFILE, 'a') as f:
        log_message = f"{timestamp} - {message}\n"
        print(log_message, end='')  # Print to console
        f.write(log_message)  # Write to log file

# Function to compare passwords
def compare_passwords(passvar, passvar2):
    if passvar == passvar2:
        return True
    else:
        log("Password mismatch")
        sys.exit(1)

# Function to validate IP address
def validate_ip(ippms):
    try:
        socket.inet_aton(ippms)
        ip_parts = list(map(int, ippms.split('.')))
        if ip_parts[0] == 127 or (ip_parts[0] == 10) or (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or (ip_parts[0] == 192 and ip_parts[1] == 168):
            return True
        else:
            log("The IP address entered is not in Private Address Space")
            log("Either '127.0.0.1' or an address in private address space is needed to claim a server")
            log("See: https://github.com/ukdtom/ClaimIt/wiki/IP-Address-requirement")
            sys.exit(1)
    except socket.error:
        log("IP is not valid")
        sys.exit(1)

# Function to get Plex Client Identifier
def get_client_identifier(ippms):
    url = f"http://{ippms}:32400/identity"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad response status

        # Parse XML response
        root = ET.fromstring(response.content)
        machineIdentifier = root.attrib.get('machineIdentifier')

        if not machineIdentifier:
            log("machineIdentifier not found in XML content")
            sys.exit(1)

        return machineIdentifier
    except requests.RequestException as e:
        log(f"Error getting client identifier: {str(e)}")
        sys.exit(1)

# Function to get login token from plex.tv
def get_login_token(username, password, client_identifier):
    url = "https://plex.tv/api/v2/users/signin"
    payload = {
        "login": username,
        "password": password,
        "X-Plex-Client-Identifier": f"ClaimIt-{client_identifier}"
    }
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()  # Raise an exception for bad response status

        # Parse XML response
        root = ET.fromstring(response.content)
        authToken = root.attrib.get('authToken')

        if not authToken:
            log("authToken not found in response")
            sys.exit(1)

        return authToken
    except requests.RequestException as e:
        log(f"Error getting login token: {str(e)}")
        sys.exit(1)

# Function to get claim token from plex.tv
def get_claim_token(user_token, client_identifier):
    url = f"https://plex.tv/api/claim/token?X-Plex-Token={user_token}&X-Plex-Client-Identifier=ClaimIt-{client_identifier}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad response status

        # Parse XML response
        root = ET.fromstring(response.content)
        token = root.attrib.get('token')

        if not token:
            log("token not found in XML content")
            sys.exit(1)

        return token
    except requests.RequestException as e:
        log(f"Error getting claim token: {str(e)}")
        sys.exit(1)

# Function to claim server
def claim_server(ippms, claim_token, client_identifier, user_token):
    url = f"http://{ippms}:32400/myplex/claim?token={claim_token}&X-Plex-Client-Identifier=ClaimIt-{client_identifier}&X-Plex-Token={user_token}"
    try:
        response = requests.post(url)
        response.raise_for_status()  # Raise an exception for bad response status

        if response.status_code == 200:
            log("Claiming server ok")
            log("")
            log("Please close your browser, reopen, and browse to http://{}:32400/web".format(ippms))
        else:
            log(f"Failed to claim server. HTTP status code: {response.status_code}")
            sys.exit(1)
    except requests.RequestException as e:
        log(f"Error claiming server: {str(e)}")
        sys.exit(1)

# Main function
def main():
    log("Script started")

    log("************************************************************************")
    log("* Script to claim a Plex Media Server")
    log("* Will prompt for")
    log("*     * plex.tv username")
    log("*     * plex.tv password")
    log("*     * IP Address of your unclaimed Plex Media Server")
    log("*")
    log("*")
    log("* Made by dane22, a Plex community member")
    log("* And Mark Walker/ZiGGiMoN, a Plex hobbyist")
    log("*")
    log("* Version 1.1.0.0")
    log("*")
    log("* To see the manual, please visit https://github.com/ukdtom/ClaimIt/wiki")
    log("************************************************************************")

    # Prompt for inputs
    uservar = input('plex.tv Username: ')
    log("Username entered")
    passvar = getpass.getpass('plex.tv Password: ')
    log("Password entered")
    passvar2 = getpass.getpass('plex.tv Password Repeated: ')
    log("Password repeated entered")
    ippms = input('IP Address of PMS server: ')
    log(f"IP Address entered: {ippms}")

    # Compare passwords
    log("Comparing entered passwords")
    compare_passwords(passvar, passvar2)
    log("Comparing entered passwords ok")

    # Validate IP address
    log("Validating IP address")
    validate_ip(ippms)
    log("Validating IP address ok")

    # Get Plex Client Identifier
    log("Getting Plex Client Identifier")
    client_identifier = get_client_identifier(ippms)
    log("Getting Plex Client Identifier ok")

    # Get Login Token
    log("Getting Login Token from plex.tv")
    user_token = get_login_token(uservar, passvar, client_identifier)
    log("Getting Login Token from plex.tv ok")

    # Get Claim Token
    log("Getting Plex Claim Token")
    claim_token = get_claim_token(user_token, client_identifier)
    log("Getting Plex Claim Token ok")

    # Claim Server
    log("Claiming server")
    claim_server(ippms, claim_token, client_identifier, user_token)
    log("Claiming server ok")

if __name__ == "__main__":
    main()
