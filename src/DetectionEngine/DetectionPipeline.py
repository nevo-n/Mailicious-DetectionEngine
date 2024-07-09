from src.DetectionEngine.DetectionModules.ExternalDataSourceModule import ExternalDataSourcesModule
from src.DBHandler.DBHandler import DBHandler
from src.consts import MALICIOUS, ERROR_CODE
import json
import re

class DetectionPipeline:
    def __init__(self, mail):
        self.modules = [ExternalDataSourcesModule(mail)]
    
    def analyze(self):
        modules_verdicts = {}
        for module in self.modules:
            modules_verdicts[module.__str__()] = module.verdict()
        return modules_verdicts

def analyze_mail(mail):
    """
    This function gets a mail and performs:
    1) saves the mail in the DB
    2) analyzes the mail (using DetectionPipeline)
    3) saves the analyzers' modules verdicts in the DB for the given mail
    4) returns the overall verdict
    """
    db_handler = DBHandler()
    data=re.sub(r'\s+', ' ', json.loads(mail)["body"]).strip()
    
    # analyze mail in all detection-modules
    modules_verdicts = DetectionPipeline(data).analyze() # TODO: insert mail handeling to detection pipeline (so we send it 'mail')

    try:
        # Save mail in DB
        create_mail_response = db_handler.save_mail(json.loads(mail))
        # Get mail's ID from responde
        mail_id = create_mail_response["id"]
    except:
        print("Unable to save mail in db")
        #return ERROR_CODE

    malicious_flag = False
    for module in modules_verdicts.keys():
        module_verdict = modules_verdicts[module]
        # get verdict_id
        if module_verdict == MALICIOUS:
            malicious_flag = True
            
        db_handler.save_mail_analysis(mail_id, module, module_verdict)
    
    # return overall verdict
    return malicious_flag


def main():
    pass

if __name__ == "__main__":
    main()