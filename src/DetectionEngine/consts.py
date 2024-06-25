MALICIOUS = 1
BENIGN = 0

# regex to find urls and websites within text
URL_REGEX = "(https{0,1}\:\/\/\S+|www\.\S+|\S+.com)" # TODO: extend maybe

# characters to strip of returned url in `extract_urls` func
REG_STRIP_CHARS = ".,:;-"

MALICIOUS_URL_THRESHOLD = 5
SUSPICIOUS_URL_THRESHOLD = 10
