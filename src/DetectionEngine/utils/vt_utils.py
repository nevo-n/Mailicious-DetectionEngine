import vt
from src.DetectionEngine.consts import (
    MALICIOUS,
    SUSPICIOUS,
    BENIGN, 
    ERROR_CODE,
    MALICIOUS_URL_THRESHOLD, 
    SUSPICIOUS_URL_THRESHOLD,
    MALICIOUS_FILE_THRESHOLD,
    SUSPICIOUS_FILE_THRESHOLD
)

class VT:
    def __init__(self, vt_client):
        self.client = vt_client

    def query_file_hash(self, hash):
        """
        Query file stats and reputation
        """
        return self.client.get_object(rf"/files/{hash}")

    def scan_file(self, file_path):
        """
        Actively scan a file
        """
        with open(file_path, "rb") as f:
            analysis = self.client.scan_file(f, wait_for_completion=True)
        return analysis
        
    def query_url(self, url):
        """
        Query a url for stats and reputation
        """
        url_id = vt.url_id(url)
        return self.client.get_object(rf"/urls/{url_id}")
    
    def scan_url(self, url):
        """
        Actively scan a url
        """
        return self.client.scan_url(url, wait_for_completion=True)

    def close(self):
        self.client.close()
    
    def provide_url_verdict(self, url):
        try:
            # try query it if it exists in VT's DB
            verdict = self.query_url(url)
            if verdict.last_analysis_stats["malicious"] >= MALICIOUS_URL_THRESHOLD:
                return MALICIOUS
            elif verdict.last_analysis_stats["suspicious"] >= SUSPICIOUS_URL_THRESHOLD or verdict.last_analysis_stats["malicious"] > 0:
                return SUSPICIOUS
        except:
            try:
                # if it does not exist in VT's DB, scan it
                verdict = self.scan_url(url)
                if verdict.stats["malicious"] >= MALICIOUS_URL_THRESHOLD:
                    return MALICIOUS
                elif verdict.stats["suspicious"] >= SUSPICIOUS_URL_THRESHOLD or verdict.stats["malicious"] > 0:
                    return SUSPICIOUS
            except:
                return ERROR_CODE
        return BENIGN
    
    def provide_file_verdict(self, hash, file_path):
        try:
            verdict = self.query_file_hash(hash)
            if verdict.last_analysis_stats["malicious"] >= MALICIOUS_FILE_THRESHOLD:
                return MALICIOUS
            elif verdict.last_analysis_stats["suspicious"] >= SUSPICIOUS_FILE_THRESHOLD or verdict.last_analysis_stats["malicious"] > 0:
                return SUSPICIOUS
        except:
            try:
                # if it does not exist in VT's DB, scan it
                verdict = self.scan_file(file_path) # file path neede
                if verdict.stats["malicious"] >= MALICIOUS_FILE_THRESHOLD:
                    return MALICIOUS
                elif verdict.stats["suspicious"] >= SUSPICIOUS_FILE_THRESHOLD or verdict.stats["malicious"] > 0:
                    return SUSPICIOUS
            except:
                return ERROR_CODE
        return BENIGN