import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.getenv("PHISHGUARD_DATABASE", BASE_DIR / "instance" / "phishguard.db"))
MODEL_PATH = Path(os.getenv("PHISHGUARD_MODEL", BASE_DIR / "models" / "url_classifier.joblib"))
SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-this-secret")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "4"))
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

