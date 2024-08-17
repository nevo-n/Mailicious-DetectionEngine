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
    URL_REGEX, 
    MALICIOUS_URL_THRESHOLD, 
    SUSPICIOUS_URL_THRESHOLD, 
    REG_STRIP_CHARS
)
from dotenv import load_dotenv
import re
import asyncio

# load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

def extract_urls(text: str) -> list[str]:
    """
    This function returns a list of urls\websites extracted from a given text
    """
    urls = re.findall(URL_REGEX, text)
    urls_stripped = [url.strip(REG_STRIP_CHARS) for url in urls]
    return urls_stripped

class VirusTotal(Module):
    def __init__(self, mail):
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.client = vt.Client(VT_API_KEY)
        self.mail = mail

    def close(self):
        self.client.close()
    
    # for future compatibility
    def query_file_hash(self, hash):
        """
        Query file stats and reputation

        hash type: SHA-256/SHA-1/MD5
        Return type: file
        some examples:
            file.size
            file.sha256
            file.type_tag
            file.last_analysis_stats
        """
        return self.client.get_object(rf"/files/{hash}")

    # for future compatibility
    def scan_file(self, file_path):
        """
        Actively scan a file
        """
        with open(file_path, "rb") as f:
            analysis = self.client.scan_file(f, wait_for_completion=True)
        return analysis
    
    # for future compatibility
    def download_file(self, hash, path):
        """
        Download a file by it's hash
        """
        with open(path, "wb") as f:
            self.client.download_file(hash, f)
    
    def query_url(self, url):
        """
        Query a url for stats and reputation

        Return type: url
        some examples:
            url.times_submitted
            url.last_analysis_stats
        """
        url_id = vt.url_id(url)
        return self.client.get_object(rf"/urls/{url_id}")
    
    def scan_url(self, url):
        """
        Actively scan a url
        """
        return self.client.scan_url(url, wait_for_completion=True)

    def provide_verdict(self):
        # extract urls from mail
        urls = extract_urls(self.mail)
        for url in urls:
            try:
                # try query it if it exists in VT's DB
                verdict = self.query_url(url)
                if verdict.last_analysis_stats["malicious"] >= MALICIOUS_URL_THRESHOLD:
                    self.close()
                    return MALICIOUS
                elif verdict.last_analysis_stats["suspicious"] >= SUSPICIOUS_URL_THRESHOLD:
                    self.close()
                    return SUSPICIOUS
            except:
                try:
                    # if it does not exist in VT's DB, scan it
                    verdict = self.scan_url(url)
                    if verdict.stats["malicious"] >= MALICIOUS_URL_THRESHOLD:
                        self.close()
                        return MALICIOUS
                    elif verdict.stats["suspicious"] >= SUSPICIOUS_URL_THRESHOLD:
                        self.close()
                        return SUSPICIOUS
                except:
                    continue
            
        self.close()
        return BENIGN
    
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
