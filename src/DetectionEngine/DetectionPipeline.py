from src.DetectionEngine.DetectionModules.ExternalDataSourceModule import ExternalDataSourcesModule
from src.DetectionEngine.DetectionModules.BlackListModule import BlackListModule
from src.DetectionEngine.DetectionModules.HebrewMailClassifierModule import HebrewMailClassifierModule
from src.DBHandler.DBHandler import DBHandler
import json

class DetectionPipeline:
    def __init__(self, active_modules_names, mail):
        self.modules = []
        for module_name in active_modules_names:
            if module_name == BlackListModule.__str__():
                self.modules.append(BlackListModule(mail))
                continue
            if module_name == ExternalDataSourcesModule.__str__():
                self.modules.append(ExternalDataSourcesModule(mail))
                continue
            if module_name == HebrewMailClassifierModule.__str__():
                self.modules.append(HebrewMailClassifierModule(mail))
                continue
    
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

    # get all detection modules the are 'turned on'
    active_modules = db_handler.get_all_analysis_types()
    active_modules_names = [entry["name"] for entry in active_modules if entry["enabled"]]
    
    # analyze mail in all detection-modules
    modules_verdicts = DetectionPipeline(active_modules_names, json.loads(mail)).analyze()

    try:
        # Save mail in DB
        create_mail_response = db_handler.save_mail(json.loads(mail))
        # Get mail's ID from responde
        mail_id = create_mail_response["id"]
    except:
        print("Unable to save mail in db")

    for module in modules_verdicts.keys():
        module_verdict = modules_verdicts[module]
        db_handler.save_mail_analysis(mail_id, module, module_verdict)
    
    # get overall verdict (block\allow)
    decision = db_handler.get_all_analysis_types(mail_id)
    
    # block = True, allow = False
    return decision


def main():
    pass

if __name__ == "__main__":
    main()