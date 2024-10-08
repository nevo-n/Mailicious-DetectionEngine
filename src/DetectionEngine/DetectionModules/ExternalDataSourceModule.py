import os
import vt
import google.generativeai as genai
from groq import Groq
import requests
import json
from src.DetectionEngine.DetectionModules.Module import Module
from src.DetectionEngine.consts import (
    MALICIOUS,
    SUSPICIOUS,
    BENIGN,
)
from src.DetectionEngine.utils.general_utils import extract_urls
from src.DetectionEngine.utils.vt_utils import VT
from dotenv import load_dotenv
import re
import asyncio

# load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

class VirusTotal(Module):
    def __init__(self, mail):
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.client = vt.Client(VT_API_KEY)
        self.mail = mail

    def provide_verdict(self):
        # extract urls from mail
        urls = extract_urls(self.mail)
        vt = VT(self.client)
        best = BENIGN
        # iterate the urls and check each one's verdict using VT
        for url in urls:
            best = max(best, vt.provide_url_verdict(url))
        vt.close()
        return best
    
    def __str__(self):
        return "VirusTotal"

class UrlScan(Module):
    def __init__(self, mail):
        self.mail = mail
    
    def submit_url_job(self, url):
        """
        Send url for analysis
        """
        api_key = URLSCAN_API_KEY
        headers = {'API-Key':f'{api_key}',
                   'Content-Type':'application/json'}
        data = {"url": f"{url}", 
                "visibility": "public"}
        return requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    
    def query_results(self, uuid):
        """
        Query analysis for return status
        """
        response = requests.get(rf'https://urlscan.io/api/v1/result/{uuid}/')
        while response.status_code == 404:
            response = requests.get(rf'https://urlscan.io/api/v1/result/{uuid}/')
        if response.status_code == 200:
            res_json = response.json()
            return res_json
        else:
            return {}
    
    def provide_verdict(self):
        # extract urls from mail
        urls = extract_urls(self.mail)
        for url in urls:
            try:
                # analyze url
                results = self.submit_url_job(url)
                uuid = results.json()["uuid"]
                res = self.query_results(uuid)
                try:
                    is_mal = res["verdicts"]["overall"]["malicious"]
                except:
                    continue
                if is_mal:
                    return MALICIOUS
            except:
                continue
        return BENIGN
    
    def __str__(self):
        return "UrlScan"

class GeminiModel(Module):
    def __init__(self, mail):
        genai.configure(api_key=GOOGLE_API_KEY)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.mail = mail
    
    def query(self, query):
        return self.model.generate_content(query)
    
    def provide_verdict(self):
        # query mail to get classification verdict
        answer = self.query(f"""
                            The following text is a mail, please classify it as 'suspicious' or 'benign'
                            and return only one word - the classification
                            (if you have doubt - please say it's 'benign')

                            The mail:
                            {self.mail}
                            """
                            )
        if "suspicious" in answer.text.lower():
            return MALICIOUS
        elif "benign" in answer.text.lower():
            return BENIGN
        else:
            return -1

    def __str__(self):
        return "Gemini"

class GroqModel(Module):
    def __init__(self, mail):
        self.client = Groq(
            api_key=GROQ_API_KEY,
        )
        self.mail = mail
    
    def query(self, query):        
        chat_completion = self.client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": query,
            }
        ],
        model="llama3-8b-8192",
        )
        return chat_completion.choices[0].message.content
    
    def provide_verdict(self):
        # query mail to get classification verdict
        query = f"""
                The following text is a mail, please classify it as 'suspicious' or 'benign'
                and return only one word - the classification
                (if you have doubt - please say it's 'benign')

                The mail:
                {self.mail}
                """
        verdict = self.query(query)
        if "suspicious" in verdict.lower():
            return MALICIOUS
        elif "benign" in verdict.lower():
            return BENIGN
        else:
            return -1 
    
    def __str__(self):
        return "Groq"

class ExternalDataSourcesModule(Module):
    def __init__(self, mail):
        # TODO: move this logic inside the sub-modules
        mail = re.sub(r'\s+', ' ', mail["body"]).strip()
        # init modules
        self.modules = [VirusTotal(mail), 
                        UrlScan(mail), 
                        GeminiModel(mail), 
                        GroqModel(mail)]
    
    def provide_verdict(self):
        verdicts = {}
        for module in self.modules:
            verdicts[module.__str__()] = module.verdict()
        if MALICIOUS in list(verdicts.values()):
            return MALICIOUS
        elif SUSPICIOUS in list(verdicts.values()):
            return SUSPICIOUS
        else:
            return BENIGN
    
    def __str__(self):
        return "ExternalDataSources"
