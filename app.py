from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from email import message_from_string
from scripts.extract_body import check_email_body
from scripts.check_headers import check_headers
from scripts.similar_domain import check_matching_domains
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
safebrowsing_api_key = os.getenv("SAFEBROWSING_API_KEY")

app = FastAPI()

# Define the request model
class EmailRequest(BaseModel):
    raw_email: str
    helo_domain: str
    sender_ip: str
    sender_domain: str
    return_path: str

@app.post("/analyze-email/")
async def analyze_email(request: EmailRequest):
    try:
        # Parse the raw email
        email_msg = message_from_string(request.raw_email)
        # Initialize spam score and description list
        spam_score = 0
        description = []


        # Check SPF, DKIM, DMARC, RBL and safebrowsing check
        score, header_description = check_headers(email_msg, request.helo_domain, request.sender_ip, request.return_path, safebrowsing_api_key)
        spam_score += score
        description.extend(header_description)

        # Extract email body
        body_text, score = check_email_body(email_msg, description)
        spam_score += score

        # Check for similar domains
        domain_similarity_score, domain_description = check_matching_domains(request.sender_domain, email_msg, description)
        spam_score += domain_similarity_score
        description.extend(domain_description)

        return {
            "spam_score": spam_score,
            "description": description,
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing email: {str(e)}")
