from src.DetectionEngine.consts import URL_REGEX, REG_STRIP_CHARS
import re
import hashlib
import base64

def extract_urls(text: str) -> list[str]:
    """
    This function returns a list of urls\websites extracted from a given text
    """
    urls = re.findall(URL_REGEX, text)
    urls_stripped = [url.strip(REG_STRIP_CHARS) for url in urls]
    return urls_stripped

def file_base64_to_sha256(base64_content):
    file_data = base64.b64decode(base64_content)
    return hashlib.sha256(file_data).hexdigest()