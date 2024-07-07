import os
import requests
from dotenv import load_dotenv
from src.consts import MALICIOUS, BENIGN, ERROR_CODE
from src.DBHandler.consts import Verdict_ID


# load db info from .env file
load_dotenv()
DB_URL = os.getenv("DB_URL")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")

class DBHandler():
    def __init__(self):
        self.headers = self._login(DB_USERNAME, DB_PASSWORD)
    
    def _login(self, username, password):
        url = f"{DB_URL}/token"
        payload = {
            "username": username,
            "password": password
        }
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            token = response.json().get("access_token")
            headers = {
                "Authorization": f"Bearer {token}"
            }
            return headers
        else:
            return None

    def save_mail(self, mail):
        # extract fields from mail's json
        sender = mail["from"]
        receiver = mail["to"]
        email_datetime = mail["date"]
        subject = mail["subject"]
        body = mail["body"]
        content = {"subject": subject, "body": body}

        return self._save_mail(sender, receiver, email_datetime, content)
    
    def _save_mail(self, sender, receiver, email_datetime, content):
        url = f"{DB_URL}/emails/"
        payload = {
            "sender": sender,
            "receiver": receiver,
            "email_datetime": email_datetime,
            "content": content
        }
        response = requests.post(url, json=payload, headers=self.headers)
        return response.json()
    
    def save_mail_analysis(self, email_id, module, module_verdict):
        # get verdict_id
        if module_verdict == MALICIOUS:
            verdict_id = Verdict_ID.MALICIOUS.value
        elif module_verdict == BENIGN:
            verdict_id = Verdict_ID.BENIGN.value
        else:
            print("error verdict: {} for module: {}".format(module_verdict, module))
            return ERROR_CODE
        # module (key) is the analysis id
        analysis_id = module
        return self._save_mail_analysis(email_id, analysis_id, verdict_id)
    
    def _save_mail_analysis(self, email_id, analysis_id, verdict_id):
        url = f"{DB_URL}/analysis/"
        payload = {
            "email_id": email_id,
            "analysis_id": analysis_id,
            "verdict_id": verdict_id
        }
        response = requests.post(url, json=payload, headers=self.headers)
        return response.json()

    def verify_login(self, username, password):
        """
        This function get a username and a password and tries to log in with 
        them to the DB server.
        Returns True if login was successful, else False
        """
        login_headers = self._login(username, password)
        return login_headers is not None
    