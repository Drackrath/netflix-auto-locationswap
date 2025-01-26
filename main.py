import time
import platform

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from service import authenticate_gmail, extract_netflix_location_link, get_unread_emails, load_netflix_credentials, mark_email_as_read
from service import ensure_chrome_binary

# Laden der Netflix-Anmeldedaten
netflix_accountname, netflix_password = load_netflix_credentials()

def click_primary_location_button(link, email_id, service):
    """Öffnet den Link und versucht entweder, den `set-primary-location-action` Button zu klicken oder loggt sich ein und markiert die E-Mail als gelesen."""
    # Konfiguration für den WebDriver
    chrome_options = Options()
    chrome_options.add_argument("--start-maximized")  # Fenster maximieren
    
    # Bestimme das Betriebssystem und wähle den entsprechenden WebDriver
    if platform.system() == "Windows":
        chrome_options.binary_location = "./chrome-win64/chrome.exe"  # Windows Binary
        service = Service('./chromedriver-win64/chromedriver.exe')  # Windows Driver
    elif platform.system() == "Linux":
        chrome_options.binary_location = "./chrome-linux64/chrome"  # Linux Binary
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


if __name__ == "__main__":
    print("Chrome Binary wird überprüft...")
    ensure_chrome_binary()  # Stelle sicher, dass der Chromedriver vorhanden ist
    
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
