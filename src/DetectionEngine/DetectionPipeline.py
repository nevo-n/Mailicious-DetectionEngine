from src.DetectionEngine.DetectionModules.ExternalDataSourceModule import ExternalDataSourcesModule
from src.DetectionEngine.consts import MALICIOUS, BENIGN

class DetectionPipeline:
    def __init__(self, mail):
        self.modules = [ExternalDataSourcesModule(mail)]

def analyze_mail(mail):
    pipeline = DetectionPipeline(mail)
    verdicts = {}
    for module in pipeline.modules:
        verdicts[module.__str__()] = module.verdict()
    if MALICIOUS in list(verdicts.values()):
        return MALICIOUS
    else:
        return BENIGN

def main():
    pass

if __name__ == "__main__":
    main()