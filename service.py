import os.path
import platform
import re
import base64
import json
import requests
import zipfile
import subprocess
import psutil

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

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

def authenticate_gmail(chrome_executable):
    """Authentifiziert den Benutzer und erstellt einen Dienst unter Verwendung des chrome_executable."""
    creds = None
    token_path = 'token.json'
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                client_secret_filename, SCOPES)
            # Using chrome_executable to open the browser for authentication
            flow.run_local_server(port=0, authorization_code_callback=None)
            subprocess.Popen([chrome_executable, flow.authorization_url()[0]])
            creds = flow.run_local_server(port=0)
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
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