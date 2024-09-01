from src.DBHandler.DBHandler import DBHandler
from src.DetectionEngine.DetectionModules.Module import Module
import re
import os
import torch
from simpletransformers.classification import ClassificationModel
import langid
from dotenv import load_dotenv
from src.DetectionEngine.consts import (
    MALICIOUS, 
    BENIGN, 
)

load_dotenv()
HEBREW_MAIL_CLASSIFIER_PATH = os.getenv("HEBREW_MAIL_CLASSIFIER_PATH")

class HebrewMailClassifierModule(Module):
    def __init__(self, mail):
        self.db_handler = DBHandler()
        self.mail = re.sub(r'\s+', ' ', mail["body"]).strip()
        self.model = self.load_model()

    def load_model(self):
        model = ClassificationModel(
            "bert", 
            f"{HEBREW_MAIL_CLASSIFIER_PATH}",
            num_labels=2,
            use_cuda=False
        )
        model.model.load_state_dict(torch.load(os.path.join(HEBREW_MAIL_CLASSIFIER_PATH, 'pytorch_model.bin'),map_location ='cpu'))
        return model

    
    def predict(self, text):
        class_dict = {1: 'PHISHING', 0: 'SAFE'}
        predictions, _ = self.model.predict([text])
        return class_dict[predictions[0]]

    def is_hebrew(self, text):
        """
        This method receives a string 'text' and returns True if it's in Hebrew and False if not
        """
        try:
            lang, _ = langid.classify(text)
            return lang == 'he'
        except Exception as e:
            return False
    
    def provide_verdict(self):
        """
        This method provides the ML model classification of the given mail text
        """
        # check if the mail is in Hebrew
        if not self.is_hebrew(self.mail):
            return BENIGN
        result = self.predict(self.mail)
        if result == "PHISHING":
            return MALICIOUS
        return BENIGN
    
    def __str__(self):
        return "HebrewMailClassifier"
