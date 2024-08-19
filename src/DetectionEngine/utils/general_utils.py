from src.DetectionEngine.consts import URL_REGEX, REG_STRIP_CHARS
import re

def extract_urls(text: str) -> list[str]:
    """
    This function returns a list of urls\websites extracted from a given text
    """
    urls = re.findall(URL_REGEX, text)
    urls_stripped = [url.strip(REG_STRIP_CHARS) for url in urls]
    return urls_stripped

def calculate_hash(file):
    hasher = hashlib.sha256()
    file.stream.seek(0)  # Ensure the stream is at the beginning
    buf = file.read()
    hasher.update(buf)
    file.stream.seek(0)  # Reset the stream position after reading
    return hasher.hexdigest()