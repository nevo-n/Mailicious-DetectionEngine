from enum import Enum

MALICIOUS = 2
SUSPICIOUS = 1
BENIGN = 0

# regex to find urls and websites within a text
URL_REGEX = "(https{0,1}\:\/\/\S+|www\.\S+|\S+\.com)[^\w]" # TODO: extend maybe

# regex to find ip address within a text
IP_ADDRESS_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# characters to strip of returned url in `extract_urls` func
REG_STRIP_CHARS = ".,:;-"

MALICIOUS_URL_THRESHOLD = 5
SUSPICIOUS_URL_THRESHOLD = 10

EXTERNAL_DOMAIN_REPUTATION_MALICIOUS_THRESHOLD = 1
EXTERNAL_DOMAIN_REPUTATION_SUSPICIOUS_THRESHOLD = 5

DISTINCT_RECEIVERS_WITH_ATTACHMENT_MALICIOUS_THRESHOLD = 10
DISTINCT_RECEIVERS_WITH_ATTACHMENT_SUSPICIOUS_THRESHOLD = 5

DISTINCT_RECEIVERS_WITH_LINK_MALICIOUS_THRESHOLD = 10
DISTINCT_RECEIVERS_WITH_LINK_SUSPICIOUS_THRESHOLD = 5

MALICIOUS_FILE_THRESHOLD = 5
SUSPICIOUS_FILE_THRESHOLD = 10

class MimeType(Enum):
    DOC = "application/msword" #.doc
    DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" #.docx
    HTML = "text/html" #.htm, .html
    JS = "text/javascript" #.js
    PDF = "application/pdf" #.pdf
    PPT = "application/vnd.ms-powerpoint" #.ppt
    PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation" #.pptx
    RAR = "application/vnd.rar" #.rar
    TAR = "application/x-tar" #.tar
    TXT = "text/plain" #.txt
    VSD = "application/vnd.visio" #.vsd
    XHTML = "application/xhtml+xml" #.xhtml
    XLS = "application/vnd.ms-excel" #.xls
    XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" #.xlsx
    XML = "application/xml" #.xml
    SEVENZIP = "application/x-7z-compressed" #.7z
    EXECUTABLE = "x-msdownload" # .exe, .dll, .com, .bat
    # TODO: missing zip, gzip

OFFICE_MIME_TYPES = [MimeType.DOC.value, MimeType.DOCX.value, 
                     MimeType.PPT.value, MimeType.PPTX.value,
                     MimeType.XLS.value, MimeType.XLSX.value,
                     MimeType.XML.value, MimeType.VSD.value,
                     MimeType.PDF.value]
