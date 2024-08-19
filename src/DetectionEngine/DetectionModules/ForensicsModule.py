import requests
import hashlib
from src.DBHandler.DBHandler import DBHandler
from src.DetectionEngine.DetectionModules.Module import Module
from src.DetectionEngine.consts import (
    MALICIOUS, 
    BENIGN,
    MimeType,
    OFFICE_MIME_TYPES
)
from src.DetectionEngine.utils.general_utils import calculate_hash
from src.FSManager.FSManager import FileSaver
from src.DetectionEngine.utils.vt_utils import VT

import asyncio
import os
VT_API_KEY = os.getenv("VT_API_KEY")

# load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("ATTACHMENTS_FILE_SYSTEM_BASE_FOLDER")

class ForensicsModule(Module):
    def __init__(self, mail):
        self.file = mail.get("attachment")
        # if there is an attachment save it in the file system
        if self.file:
            self.file_path = FileSaver().save_file(self.file)
        # if there isn't - return BENIGN
        else:
            return BENIGN
        self.db_handler = DBHandler()
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.client = vt.Client(VT_API_KEY)

    def hash_verdict(self, hash):
        headers = {'Accept': 'application/json'}
        r = requests.get('https://labs.inquest.net/api/dfi/search/hash/sha256', params={'hash': f'{hash}'}, headers=headers)
        return r.json()
    
    def upload_file_for_scan(self, file):
        # Read the file content as binary
        file_content = self.file.read()
        self.file.seek(0)
        # the maximum file size that can be uploaded is 15MB
        api_url = "https://labs.inquest.net/api/dfi/upload"
        headers = {
            'Content-Type': 'application/octet-stream',
            'Accept': 'application/json'
        }
        return requests.post(api_url, headers=headers, data=file_content)

    def provide_verdict(self):
        """
        Given a file (a mail attachment) - return wether it is malicious\suspicious\benign
        """
        hash = calculate_hash(self.file)

        file_mime_type = self.file.mimetype
        if file_mime_type in OFFICE_MIME_TYPES:
            hash_verdict = self.hash_verdict(hash)
            if ((hash_verdict["data"] and hash_verdict["success"]) and 
                hash_verdict["data"][0]['classification'] == 'MALICIOUS'):
                self.client.close()
                return MALICIOUS
            else:
                # send file for analysis
                hash_for_verdict = self.upload_file_for_scan(self.file)
                verdict = self.hash_verdict(hash_for_verdict)
                if ((hash_verdict["data"] and hash_verdict["success"]) and 
                    hash_verdict["data"][0]['classification'] == 'MALICIOUS'):
                    self.client.close()
                    return MALICIOUS
        elif file_mime_type in MimeType.EXECUTABLE.value:
            vt = VT(self.client)
            verdict = vt.provide_file_verdict(hash, self.file_path)
            vt.close()
            return verdict
        
        self.client.close()
        return BENIGN
    
    def __str__(self):
        return "Forensics"
