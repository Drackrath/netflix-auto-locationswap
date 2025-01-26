import os.path
import platform
import re
import base64
import json
import requests
import zipfile
import subprocess
import psutil
import webbrowser
import time

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import threading
from flask import Flask, request

# Globale Variablen
client_secret_filename = "client_secret.json"
netflix_client_credentials = "netflix_client_credentials.json"

# Berechtigungen für die Gmail API
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly'
]

# Funktion, um die Netflix-Anmeldedaten aus der JSON-Datei zu laden
def load_netflix_credentials():
    with open('netflix_client_credentials.json', 'r') as file:
        credentials = json.load(file)
    return credentials['netflix_accountname'], credentials['netflix_password']

def check_chrome_headless(chrome_executable):
    """Prüft, ob Chrome im Headless-Modus läuft und öffnet die Sitzung. Falls nicht, startet es im Headless-Modus."""
    chrome_running = False
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        if 'chrome' in proc.info['name'].lower():
            # Check if Chrome is running in headless mode by inspecting the command line arguments
            if '--headless' in proc.info['cmdline']:
                print("Chrome is running in headless mode.")
                chrome_running = True
                break
            else:
                print("Chrome is running in non-headless mode.")
                return False

    if not chrome_running:
        print("Chrome is not running. Starting Chrome in headless mode...")
        # Start Chrome in headless mode and open remote debugging session
        subprocess.Popen([chrome_executable, '--headless', '--remote-debugging-port=9222'])
        return True
    
    return True

def generate_openssl_certs(cert_dir='certs', private_key_filename='private_key.pem', cert_filename='cert.pem', csr_filename='cert_request.csr'):
    """
    Generates a private key, certificate signing request (CSR), and self-signed certificate using OpenSSL.

    :param cert_dir: Directory to store the certificates (default is 'certs')
    :param private_key_filename: Filename for the private key (default is 'private_key.pem')
    :param cert_filename: Filename for the certificate (default is 'cert.pem')
    :param csr_filename: Filename for the certificate signing request (default is 'cert_request.csr')
    :return: None
    """
    # Ensure the certificate directory exists
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    # Full paths to the certificate files
    private_key_path = os.path.join(cert_dir, private_key_filename)
    csr_path = os.path.join(cert_dir, csr_filename)
    cert_path = os.path.join(cert_dir, cert_filename)

    # Generate private key
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-out', private_key_path], check=True)
    print(f"Private key saved to {private_key_path}")

    # Generate CSR
    subprocess.run(['openssl', 'req', '-new', '-key', private_key_path, '-out', csr_path], check=True)
    print(f"CSR saved to {csr_path}")

    # Generate self-signed certificate
    subprocess.run(['openssl', 'x509', '-req', '-in', csr_path, '-signkey', private_key_path, '-out', cert_path], check=True)
    print(f"Certificate saved to {cert_path}")

app = Flask(__name__)

# Path to your certificates
CERT_FILE = './certs/cert.pem'
KEY_FILE = './certs/private_key.pem'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def run_local_server(flow):
    """Runs a Flask server to handle the redirect after OAuth authentication."""
    @app.route('/')
    def authorize():
        # Extract the authorization code from the request URL
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        # Save the credentials
        creds = flow.credentials
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
        
        print("Authentication complete!")
        return 'Authentication complete. You can close this window.'
    
    # Run Flask with SSL context
    app.run(host='localhost', port=8080, ssl_context=(CERT_FILE, KEY_FILE), debug=True, use_reloader=False)

def authenticate_gmail(chrome_executable, client_secret_filename):
    """Authenticates the user and creates a service using chrome_executable."""
    creds = None
    token_path = 'token.json'
    
    # Check if token file exists and is non-empty
    if os.path.exists(token_path):
        try:
            with open(token_path, 'r') as token_file:
                # Ensure the file isn't empty
                if token_file.read().strip():
                    creds = Credentials.from_authorized_user_file(token_path, SCOPES)
                    print("Token loaded successfully.")
                else:
                    print("Token file is empty. Re-authentication is required.")
                    creds = None
        except Exception as e:
            print(f"Error loading token: {e}")
            creds = None
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(client_secret_filename, SCOPES)
            
            # Manually set the redirect URI to point to your local server over HTTPS
            redirect_uri_manual = 'https://localhost:8080/'  # Use HTTPS here
            flow.redirect_uri = redirect_uri_manual
            print("Redirect URI set to:", flow.redirect_uri)
            auth_url, _ = flow.authorization_url(prompt='consent')
            print(f"Please visit this URL to authorize: {auth_url}")
            
            # Open the URL in Chrome
            webbrowser.register('chrome-dev', None, webbrowser.BackgroundBrowser(chrome_executable))
            webbrowser.get('chrome-dev').open(auth_url)

            # Start a local server to handle the redirect after user completes authentication
            thread = threading.Thread(target=run_local_server, args=(flow,))
            thread.start()
            
            # Wait for the server to handle the redirect and complete authentication
            print("Waiting for authentication to complete...")
            thread.join()  # Ensure that the thread finishes execution
            
        # Load the credentials after waiting for the OAuth flow to complete
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

        # Save the credentials for the next run
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
            print("Token saved.")
    
    return build('gmail', 'v1', credentials=creds)



def get_unread_emails(service):
    """Holt ungelesene E-Mails."""
    results = service.users().messages().list(userId='me', q="is:unread").execute()
    messages = results.get('messages', [])
    if not messages:
        return []
    emails = []
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        email_data = {
            'id': msg['id'],
            'snippet': msg['snippet'],
            'payload': msg['payload']
        }
        emails.append(email_data)
    return emails

def extract_netflix_location_link(payload):
    """Extrahiert den Netflix-Link zur Standortaktualisierung."""
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/html' and 'body' in part and 'data' in part['body']:
                html_content = part['body']['data']
                html_content = base64.urlsafe_b64decode(html_content).decode('utf-8')
                links = re.findall(r'(https?://\S+)', html_content)
                for link in links:
                    if "https://www.netflix.com/account/update-primary-location" in link:
                        return link
    return None

def mark_email_as_read(service, email_id):
    """Markiert eine E-Mail als gelesen."""
    try:
        # Aktualisiere den Status der E-Mail auf 'gelesen'
        msg = service.users().messages().modify(userId='me', id=email_id, body={'removeLabelIds': ['UNREAD']}).execute()
        print(f"E-Mail {email_id} wurde als gelesen markiert.")
    except Exception as e:
        print(f"Fehler beim Markieren der E-Mail als gelesen: {e}")
        
        
def ensure_chrome_binary():
    """Ensures that the chrome-linux64 directory exists. If not, downloads and extracts it."""
    if platform.system() == "Windows":
        chrome_dir = "./chrome-win64/"
        chrome_executable = "./chrome-win64/chrome.exe"
        chrome_zip_url = "https://storage.googleapis.com/chrome-for-testing-public/132.0.6834.110/win64/chrome-win64.zip"
        chrome_zip_file = "chrome-win64.zip"
    elif platform.system() == "Linux":
        chrome_dir = "./chrome-linux64/"
        chrome_executable = "./chrome-linux64/chrome"
        chrome_zip_url = "https://storage.googleapis.com/chrome-for-testing-public/132.0.6834.110/linux64/chrome-linux64.zip"
        chrome_zip_file = "chrome-linux64.zip"

    # Check if the chrome-linux64 directory already exists
    if not os.path.exists(chrome_dir):
        print("Chrome binary nicht gefunden. Download gestartet...")

        # Download the zip file
        response = requests.get(chrome_zip_url, stream=True)
        if response.status_code == 200:
            with open(chrome_zip_file, "wb") as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            print(f"Downloaded {chrome_zip_file}")
        else:
            raise Exception(f"Download fehlgeschlagen. HTTP Status: {response.status_code}")

        # Extract the zip file
        with zipfile.ZipFile(chrome_zip_file, "r") as zip_ref:
            zip_ref.extractall(".")
        print(f"Extracted {chrome_zip_file} to {chrome_dir}")

        # Clean up the zip file
        os.remove(chrome_zip_file)
        print(f"Removed the zip file {chrome_zip_file}")
        
        return chrome_executable

    else:
        print("Chrome binary gefunden...")
        return chrome_executable