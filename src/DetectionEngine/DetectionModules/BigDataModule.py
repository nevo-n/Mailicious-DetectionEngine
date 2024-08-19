from src.DBHandler.DBHandler import DBHandler
from src.DetectionEngine.DetectionModules.Module import Module
from src.DetectionEngine.consts import (
    MALICIOUS,
    SUSPICIOUS,
    BENIGN,
    EXTERNAL_DOMAIN_REPUTATION_MALICIOUS_THRESHOLD,
    EXTERNAL_DOMAIN_REPUTATION_SUSPICIOUS_THRESHOLD,
    DISTINCT_RECEIVERS_WITH_ATTACHMENT_MALICIOUS_THRESHOLD,
    DISTINCT_RECEIVERS_WITH_ATTACHMENT_SUSPICIOUS_THRESHOLD,
    DISTINCT_RECEIVERS_WITH_LINK_MALICIOUS_THRESHOLD,
    DISTINCT_RECEIVERS_WITH_LINK_SUSPICIOUS_THRESHOLD
)
from src.DetectionEngine.utils.general_utils import extract_urls
import re

class BigDataModule(Module):
    def __init__(self, mail):
        self.mail = mail
        self.db_handler = DBHandler()

    def provide_verdict(self):
        """
        This method check all the BigData module's detectors and returns the 'highest' verdict received
        """
        # receivers:
        # r1@example.com, r2@example.com, ...
        first_receiver = self.mail["to"].split(", ")[0]
        first_receiver_domain = first_receiver.split("@")[1]
        sender_domain = self.mail["from"].split("@")[1]

        best = BENIGN

        # if external domain
        if (first_receiver_domain != sender_domain):
            sender_domain_reputation = self.db_handler.sender_domain_reputation(sender_domain)
            if sender_domain_reputation <= EXTERNAL_DOMAIN_REPUTATION_MALICIOUS_THRESHOLD:
                best = MALICIOUS
            elif sender_domain_reputation <= EXTERNAL_DOMAIN_REPUTATION_SUSPICIOUS_THRESHOLD:
                best = max(best, SUSPICIOUS)

        # if mail with attachments
        if self.mail["attachment"]:
            sender_distinct_receivers_with_attachment_today = self.db_handler.get_sender_day_mails_with_attachment_reputation(self.mail["from"])
            if sender_distinct_receivers_with_attachment_today >= DISTINCT_RECEIVERS_WITH_ATTACHMENT_MALICIOUS_THRESHOLD:
                best = MALICIOUS
            elif sender_distinct_receivers_with_attachment_today >= DISTINCT_RECEIVERS_WITH_ATTACHMENT_SUSPICIOUS_THRESHOLD:
                best = max(best, SUSPICIOUS)
        
        # extract urls from mail
        content = re.sub(r'\s+', ' ', self.mail["body"]).strip()
        urls = extract_urls(content)
        if urls:
            sender_distinct_receivers_with_link_today = self.db_handler.get_sender_day_mails_with_link_reputation(self.mail["from"])
            if sender_distinct_receivers_with_link_today >= DISTINCT_RECEIVERS_WITH_LINK_MALICIOUS_THRESHOLD:
                best = MALICIOUS
            elif sender_distinct_receivers_with_link_today >= DISTINCT_RECEIVERS_WITH_LINK_SUSPICIOUS_THRESHOLD:
                best = max(best, SUSPICIOUS)

        return best
    
    def __str__(self):
        return "BigData"
