import time
import os.path
import re
import base64
import json
import platform

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


client_secret_filename = "client_secret.json"
netflix_client_credentials = "netflix_client_credentials.json"

# Funktion, um die Netflix-Anmeldedaten aus der JSON-Datei zu laden
def load_netflix_credentials():
    with open('netflix_client_credentials.json', 'r') as file:
        credentials = json.load(file)
    return credentials['netflix_accountname'], credentials['netflix_password']

# Laden der Netflix-Anmeldedaten
netflix_accountname, netflix_password = load_netflix_credentials()

# Berechtigungen für die Gmail API
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly'
]

def authenticate_gmail():
    """Authentifiziert den Benutzer und erstellt einen Dienst."""
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

def click_primary_location_button(link, email_id, service):
    """Öffnet den Link und versucht entweder, den `set-primary-location-action` Button zu klicken oder loggt sich ein und markiert die E-Mail als gelesen."""
    # Konfiguration für den WebDriver
    chrome_options = Options()
    chrome_options.add_argument("--start-maximized")  # Fenster maximieren
    
    # Bestimme das Betriebssystem und wähle den entsprechenden WebDriver
    if platform.system() == "Windows":
        service = Service('./chromedriver-win64/chromedriver.exe')  # Windows Driver
    elif platform.system() == "Linux":
        service = Service('./chromedriver-linux64/chromedriver')  # Linux Driver

    # Browser starten
    driver = webdriver.Chrome(service=service, options=chrome_options)
    try:
        driver.get(link)
        time.sleep(3)  # Warte auf das Laden der Seite

        try:
            # Versuche, den "Set Primary Location"-Button zu finden
            button = driver.find_element(By.CSS_SELECTOR, '[data-uia="set-primary-location-action"]')
            ActionChains(driver).move_to_element(button).click().perform()
            print("Button 'Set Primary Location' erfolgreich geklickt.")
            time.sleep(3)  # Warte, falls eine weitere Aktion erforderlich ist

            # Markiere die E-Mail als gelesen
            mark_email_as_read(service, email_id)

        except Exception:
            # Wenn der Button nicht gefunden wird, logge dich ein
            print("Button 'Set Primary Location' nicht gefunden, versuche, dich einzuloggen...")

            # Warten, bis die Login-Elemente sichtbar werden
            try:
                email_field = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, '[name="userLoginId"]'))
                )
                password_field = driver.find_element(By.CSS_SELECTOR, '[name="password"]')
                login_button = driver.find_element(By.CSS_SELECTOR, '[data-uia="login-submit-button"]')

                # Fülle E-Mail und Passwort aus
                email_field.send_keys(netflix_accountname)
                password_field.send_keys(netflix_password)
                login_button.click()
                print("Login-Daten eingegeben und Login-Button geklickt.")
                time.sleep(5)  # Warte auf den Login-Vorgang

                # Versuche nach dem Login, den "Set Primary Location"-Button erneut zu finden
                try:
                    button = driver.find_element(By.CSS_SELECTOR, '[data-uia="set-primary-location-action"]')
                    ActionChains(driver).move_to_element(button).click().perform()
                    print("Button 'Set Primary Location' nach Login erfolgreich geklickt.")
                    
                    # Markiere die E-Mail als gelesen
                    mark_email_as_read(service, email_id)
                except Exception as e:
                    print(f"Fehler beim Finden des Buttons nach dem Login: {e}")
            except Exception as e:
                print(f"Fehler beim Login-Versuch: {e}")
    except Exception as e:
        print(f"Fehler beim Zugriff auf den Link: {e}")
    finally:
        driver.quit()  # Schließt den Browser


def mark_email_as_read(service, email_id):
    """Markiert eine E-Mail als gelesen."""
    try:
        # Aktualisiere den Status der E-Mail auf 'gelesen'
        msg = service.users().messages().modify(userId='me', id=email_id, body={'removeLabelIds': ['UNREAD']}).execute()
        print(f"E-Mail {email_id} wurde als gelesen markiert.")
    except Exception as e:
        print(f"Fehler beim Markieren der E-Mail als gelesen: {e}")


if __name__ == "__main__":
    print("Authentifizierung...")
    service = authenticate_gmail()

    print("Überwachung auf ungelesene E-Mails gestartet...")
    try:
        while True:
            emails = get_unread_emails(service)
            if emails:
                print(f"{len(emails)} ungelesene E-Mail(s) gefunden:")
                for email in emails:
                    print(f"ID: {email['id']} | Vorschau: {email['snippet']}")
                    link = extract_netflix_location_link(email['payload'])
                    if link:
                        print(f"Öffne Netflix-Link: {link}")
                        click_primary_location_button(link)  # Klicke auf den Button
                        break  # Öffne nur den ersten passenden Link und beende die Schleife
            else:
                print("Keine ungelesenen E-Mails gefunden.")
            time.sleep(30)  # Warte 30 Sekunden vor der nächsten Überprüfung
    except KeyboardInterrupt:
        print("Überwachung beendet.")
