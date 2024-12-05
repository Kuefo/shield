import os
import json
import requests
import webbrowser
import logging
import time
import random
import threading
from urllib.parse import urlencode
from requests.exceptions import HTTPError, Timeout
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64
import hashlib
from termcolor import colored

load_dotenv()

logging.basicConfig(level=logging.INFO)

def generate_encryption_key():
    key = Fernet.generate_key()
    with open("token_encryption.key", "wb") as key_file:
        key_file.write(key)

def load_encryption_key():
    with open("token_encryption.key", "rb") as key_file:
        return key_file.read()

def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

def get_random_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
    ]
    return random.choice(user_agents)

def get_random_proxy():
    proxy_pool = [
        "http://127.0.0.1:8080",
        "http://proxy1.example.com:8080",
        "http://proxy2.example.com:8080"
    ]
    return random.choice(proxy_pool)

def store_token_securely(access_token, refresh_token):
    key = load_encryption_key()
    encrypted_access_token = encrypt_data(access_token, key)
    encrypted_refresh_token = encrypt_data(refresh_token, key)
    with open("secure_tokens.json", "w") as token_file:
        json.dump({
            "access_token": encrypted_access_token.decode(),
            "refresh_token": encrypted_refresh_token.decode()
        }, token_file)

def load_secure_token():
    with open("secure_tokens.json", "r") as token_file:
        tokens = json.load(token_file)
        key = load_encryption_key()
        access_token = decrypt_data(tokens['access_token'].encode(), key)
        refresh_token = decrypt_data(tokens['refresh_token'].encode(), key)
        return access_token, refresh_token

def get_authorization_code(base_url, client_id, redirect_uri):
    authorize_params = {
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'identify email connections rpc webhook.incoming messages.read',
        'redirect_uri': redirect_uri,
    }
    authorize_url = f"{base_url}/oauth2/authorize?{urlencode(authorize_params)}"
    logging.info(f"Opening browser for user authorization: {authorize_url}")
    webbrowser.open(authorize_url)
    return input("Enter the authorization code from the URL: ")

def exchange_code_for_token(session, base_url, client_id, client_secret, authorization_code, redirect_uri):
    token_payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': redirect_uri,
    }
    token_url = f"{base_url}/api/oauth2/token"
    
    retries = 5
    for attempt in range(retries):
        try:
            response = session.post(token_url, data=token_payload, headers={"User-Agent": get_random_user_agent(), "Proxy": get_random_proxy()})
            response.raise_for_status()
            token_data = response.json()
            if 'access_token' not in token_data:
                logging.error("Access token not found in response.")
                raise Exception("Failed to retrieve access token.")
            return token_data['access_token'], token_data.get('refresh_token', None)
        except HTTPError as http_err:
            logging.error(f"HTTP error occurred during token exchange: {http_err}")
        except Timeout:
            logging.error("Timeout occurred during token exchange.")
        except Exception as err:
            logging.error(f"Unexpected error occurred: {err}")
        if attempt < retries - 1:
            logging.info(f"Retrying... Attempt {attempt + 2}/{retries}")
            time.sleep(2 ** attempt)

    raise Exception("Failed to exchange code for token after multiple retries")

def get_user_data(session, base_url, access_token):
    api_headers = {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": get_random_user_agent(),
        "Proxy": get_random_proxy()
    }
    api_endpoint = f"{base_url}/api/v10/users/@me"
    
    retries = 3
    for attempt in range(retries):
        try:
            response = session.get(api_endpoint, headers=api_headers)
            response.raise_for_status()
            return response.json()
        except HTTPError as http_err:
            logging.error(f"HTTP error occurred during user data retrieval: {http_err}")
        except Timeout:
            logging.error("Timeout occurred during user data retrieval.")
        except Exception as err:
            logging.error(f"Unexpected error occurred: {err}")
        if attempt < retries - 1:
            logging.info(f"Retrying... Attempt {attempt + 2}/{retries}")
            time.sleep(2 ** attempt)

    raise Exception("Failed to retrieve user data after multiple retries")

def refresh_access_token(session, base_url, client_id, client_secret, refresh_token, redirect_uri):
    token_payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'redirect_uri': redirect_uri,
    }
    token_url = f"{base_url}/api/oauth2/token"
    
    retries = 5
    for attempt in range(retries):
        try:
            response = session.post(token_url, data=token_payload, headers={"User-Agent": get_random_user_agent(), "Proxy": get_random_proxy()})
            response.raise_for_status()
            token_data = response.json()
            if 'access_token' not in token_data:
                logging.error("Access token not found in token refresh response.")
                raise Exception("Failed to refresh access token.")
            return token_data['access_token']
        except HTTPError as http_err:
            logging.error(f"HTTP error occurred during token refresh: {http_err}")
        except Timeout:
            logging.error("Timeout occurred during token refresh.")
        except Exception as err:
            logging.error(f"Unexpected error occurred: {err}")
        if attempt < retries - 1:
            logging.info(f"Retrying... Attempt {attempt + 2}/{retries}")
            time.sleep(2 ** attempt)

    raise Exception("Failed to refresh access token after multiple retries")

def display_gui():
    print(colored("=================================================", "cyan"))
    print(colored("           FUCK DISCORD USERS ", "yellow"))
    print(colored("=================================================", "cyan"))
    print(colored("The most powerful tool for retrieving, managing and", "green"))
    print(colored("monitoring Discord user data for elite operations.", "green"))
    print(colored("Powered by highly advanced APT strategies to infiltrate,", "green"))
    print(colored("access, and control Discord user information.", "green"))
    print(colored("=================================================", "cyan"))
    print(colored("1. Start Authentication Process", "green"))
    print(colored("2. View User Information", "blue"))
    print(colored("3. Refresh Access Token", "red"))
    print(colored("4. Exit", "magenta"))
    print(colored("=================================================", "cyan"))

def main():
    base_url = os.getenv('BASE_URL', "https://discord.com")
    client_id = os.getenv('CLIENT_ID', "YOUR_CLIENT_ID")
    client_secret = os.getenv('CLIENT_SECRET', "YOUR_CLIENT_SECRET")
    redirect_uri = os.getenv('REDIRECT_URI', "http://localhost:8000/callback")
    
    with requests.Session() as session:
        while True:
            display_gui()
            choice = input(colored("Enter your choice: ", "yellow"))
            
            if choice == "1":
                try:
                    authorization_code = get_authorization_code(base_url, client_id, redirect_uri)
                    access_token, refresh_token = exchange_code_for_token(session, base_url, client_id, client_secret, authorization_code, redirect_uri)
                    store_token_securely(access_token, refresh_token)
                    logging.info(colored("Authentication successful!", "green"))
                except Exception as e:
                    logging.error(f"Authentication failed: {str(e)}")
            elif choice == "2":
                try:
                    access_token, refresh_token = load_secure_token()
                    user_data = get_user_data(session, base_url, access_token)
                    print(colored("User Data retrieved successfully:", "green"))
                    print(json.dumps(user_data, indent=4))
                except Exception as e:
                    logging.error(f"Failed to retrieve user data: {str(e)}")
            elif choice == "3":
                try:
                    access_token, refresh_token = load_secure_token()
                    new_access_token = refresh_access_token(session, base_url, client_id, client_secret, refresh_token, redirect_uri)
                    store_token_securely(new_access_token, refresh_token)
                    logging.info(colored("Access token refreshed successfully!", "green"))
                except Exception as e:
                    logging.error(f"Failed to refresh access token: {str(e)}")
            elif choice == "4":
                logging.info(colored("Exiting FUCK DISCORD USERS tool...", "magenta"))
                break
            else:
                logging.error(colored("Invalid choice, please select a valid option.", "red"))

if __name__ == "__main__":
    main()