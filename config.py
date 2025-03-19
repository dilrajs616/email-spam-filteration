import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY")
SPF_FAIL_SCORE = int(os.getenv("SPF_FAIL_SCORE", 0))
SPF_PASS_SCORE = int(os.getenv("SPF_PASS_SCORE", 0))
DKIM_FAIL_SCORE = int(os.getenv("DKIM_FAIL_SCORE", 0))
DKIM_PASS_SCORE = int(os.getenv("DKIM_PASS_SCORE", 0))
DMARC_FAIL_SCORE = int(os.getenv("DMARC_FAIL_SCORE", 0))
DMARC_PASS_SCORE = int(os.getenv("DMARC_PASS_SCORE", 0))
RBL_FAIL_SCORE = int(os.getenv("RBL_FAIL_SCORE", 0))
RBL_PASS_SCORE = int(os.getenv("RBL_PASS_SCORE", 0))
SAFEBROWSING_FAIL_SCORE = int(os.getenv("SAFEBROWSING_FAIL_SCORE", 0))
SAFEBROWSING_PASS_SCORE = int(os.getenv("SAFEBROWSING_PASS_SCORE", 0))
DOMAIN_SIMILARITY_SCORE = int(os.getenv("DOMAIN_SIMILARITY_SCORE", 0))
DOMAIN_NON_SIMILARITY_SCORE = int(os.getenv("DOMAIN_NON_SIMILARITY_SCORE", 0))