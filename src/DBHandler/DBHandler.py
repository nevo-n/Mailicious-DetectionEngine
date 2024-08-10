import os
import requests
from dotenv import load_dotenv
from src.consts import MALICIOUS, BENIGN, ERROR_CODE
from src.DBHandler.consts import Verdict_ID
from datetime import datetime

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
        headers = {
            "Content-Type": "application/json",
            "accept": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)
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
        date_str = mail["date"]
        parsed_date = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
        email_datetime = parsed_date.strftime('%Y-%m-%dT%H:%M:%S')
        subject = mail["subject"]
        content = mail["body"]

        return self._save_mail(sender, receiver, email_datetime, subject, content)
    
    def _save_mail(self, sender, receiver, email_datetime, subject, content):
        url = f"{DB_URL}/emails/"
        payload = {
            "sender": sender,
            "recipients": receiver,
            "email_datetime": email_datetime,
            "subject": subject,
            "content": content
        }
        response = requests.post(url, json=payload, headers=self.headers)
        return response.json()
    
    def save_mail_analysis(self, email_id, module, module_verdict):
        # get verdict_id
        response_verdicts = self._get_all_verdicts(self.headers)
        if module_verdict == MALICIOUS:
            verdict = Verdict_ID.MALICIOUS.value
        elif module_verdict == BENIGN:
            verdict = Verdict_ID.BENIGN.value
        else:
            print("error verdict: {} for module: {}".format(module_verdict, module))
            return ERROR_CODE

        verdict_id = -1
        for item in response_verdicts:
            if item["name"] == verdict:
                verdict_id = item["id"]
                break
        
        # get analysis id
        response_analysis = self._get_all_analysis_types(self.headers)
        
        analysis_id = -1
        for item in response_analysis:
            if item["name"] == module:
                analysis_id = item["id"]
                break

        if verdict_id == -1 or analysis_id == -1:
            return ERROR_CODE

        return self._save_mail_analysis(email_id, analysis_id, verdict_id)
    
    def _save_mail_analysis(self, email_id, analysis_id, verdict_id):
        url = f"{DB_URL}/analysis/"
        payload = {
            "email_id": email_id,
            "analysis_id": analysis_id,
            "verdict_id": verdict_id,
            "created_on": datetime.now().isoformat()
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

    def _get_all_verdicts(self, headers):
        url = f"{DB_URL}/enum_verdicts/"
        response = requests.get(url, headers=headers)
        return response.json()

    def _get_all_analysis_types(self, headers):
        url = f"{DB_URL}/enum_modules/"
        response = requests.get(url, headers=headers)
        return response.json()
    
    def get_blacklists_grouped(self):
        url = f"{DB_URL}/blacklist/grouped"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def get_all_analysis_types(self):
        url = f"{DB_URL}/enum_modules/"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def get_email_decision(self, email_id):
        url = f"{DB_URL}/emails/decision/{email_id}"
        response = requests.get(url, headers=self.headers)
        return response.json()