MALICIOUS = 1
BENIGN = 0

# regex to find urls and websites within a text
URL_REGEX = "(https{0,1}\:\/\/\S+|www\.\S+|\S+\.com)[^\w]" # TODO: extend maybe

# regex to find ip address within a text
IP_ADDRESS_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# characters to strip of returned url in `extract_urls` func
REG_STRIP_CHARS = ".,:;-"

MALICIOUS_URL_THRESHOLD = 5
SUSPICIOUS_URL_THRESHOLD = 10
