from src.DBHandler.DBHandler import DBHandler
from src.DetectionEngine.DetectionModules.Module import Module
from src.DetectionEngine.consts import (
    MALICIOUS, 
    BENIGN, 
)

class BlackListModule(Module):
    def __init__(self, mail):
        self.mail = mail
        self.db_handler = DBHandler()
        self.blacklist_data = self.db_handler.get_blacklists_grouped()
    
    def _check_sender_domain(self, domain):
        """
        This method checks whether the given mail sender mail
        is from the domain 'domain'
        """
        return self.mail["sender"].lower().endswith(domain.lower())

    def _check_mail_subject(self, subject):
        """
        This method checks whether the given mail subject contains
        the substring 'subject'
        """
        return subject.lower() in self.mail["subject"].lower()

    def _check_mail_asn(self, asn):
        """
        This method checks whether the given mail ASNs contains
        the given 'asn'
        """
        pass # TODO

    def _check_sender_country(self, country):
        """
        This method checks whether one of the given mail ASNs 
        IPs are from the country 'country'
        """
        pass # TODO

    def provide_verdict(self):
        """
        For every field in the BlackList data check on the mail 
        """
        for entry in self.blacklist_data:
            # Get id matching field
            field = entry["field_name"]
            values_array = entry["values"].split(",")

            # Check against the suitable blacklist cfunction
            if field.lower() == "domain":
                for value in values_array:
                    if self._check_sender_domain(value):
                        return MALICIOUS
            elif field.lower() == "subject":
                for value in values_array:
                    if self._check_mail_subject(value):
                        return MALICIOUS
            elif field.lower() == "asn":
                for value in values_array:
                    if self._check_mail_asn(value):
                        return MALICIOUS
            pass
        
        return BENIGN
    
    def __str__(self):
        return "BlackList"
