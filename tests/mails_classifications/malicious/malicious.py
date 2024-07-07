SAFE_PLACEHOLDER = "<<safe_placeholder>>"
# splitted with safe placeholder to avoid clicking
MAL_URL = ""

MALICIOUS_EMAIL_CONTENT = f"""
                        Hey all!
                        unfortunatly our wonderful boss is leaving us for another company,
                        he gave us a nice goodbye present right here:
                        {MAL_URL.replace(SAFE_PLACEHOLDER, "")}
                        please get in and help yourself!
                        """
