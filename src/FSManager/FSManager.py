import os
import hashlib
import datetime
from src.DetectionEngine.utils.general_utils import calculate_hash
from dotenv import load_dotenv

# load API keys from .env file
load_dotenv()
ATTACHMENTS_FILE_SYSTEM_BASE_FOLDER = os.getenv("ATTACHMENTS_FILE_SYSTEM_BASE_FOLDER")

class FileSaver:
    """
    The FileSaver is the local solution for S3 Buckets or file servers. In order to save email attachments we want some sort of 
    file system that saves them locally or remotely in order to be able to investigate them further.
    This class gives the local solution mentioned above - the FileSaver receives a file object (<class 'werkzeug.datastructures.FileStorage'>)
    and saves it in the following path format: "<ATTACHMENTS_FILE_SYSTEM_BASE_FOLDER>\<current date>\<file's sha256>"
    """
    def __init__(self, base_folder=f"{ATTACHMENTS_FILE_SYSTEM_BASE_FOLDER}"):
        self.base_folder = base_folder
        if not os.path.exists(self.base_folder):
            os.makedirs(self.base_folder)

    def save_file(self, file):
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")

        file_hash = calculate_hash(file)

        # Create the folder path
        folder_path = os.path.join(self.base_folder, current_date)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        # Create the destination file path
        destination_path = os.path.join(folder_path, file_hash)

        # Save the file
        file.stream.seek(0)  # Ensure the stream is at the beginning
        with open(destination_path, "wb") as dest_file:
            dest_file.write(file.read())

        # Return the absolute path
        return os.path.abspath(destination_path)
