from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from email import message_from_string
from scripts.check_headers import check_headers
from scripts.similar_domain import check_matching_domains
from scripts.check_body import check_email_body

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
        # Check email size
        MAX_EMAIL_SIZE = 5 * 1024 * 1024  # 5MB
        if len(request.raw_email.encode("utf-8")) > MAX_EMAIL_SIZE:
            raise HTTPException(status_code=413, detail="Email size exceeds 5MB limit")

        # Parse the raw email
        email_msg = message_from_string(request.raw_email)
        if not email_msg:
            raise ValueError("Failed to parse email")

        # Initialize spam score and description list
        spam_score = 0
        description = []

        # Check SPF, DKIM, DMARC, RBL, and Safe Browsing
        header_score = check_headers(email_msg, request.helo_domain, request.sender_ip, request.return_path, description)
        spam_score += header_score

        # Check for similar domains
        domain_similarity_score = check_matching_domains(request.sender_domain, email_msg, description)
        spam_score += domain_similarity_score

        # Extract and analyze email body
        body_score = check_email_body(email_msg, description)
        spam_score += body_score

        # Ensure spam score is non-negative
        spam_score = max(spam_score, 0)

        return {
            "spam_score": spam_score,
            "description": description,
        }

    except ValueError as ve:
        raise HTTPException(status_code=422, detail=f"Invalid email format: {str(ve)}")
    except HTTPException:
        raise  # Re-raise known HTTP exceptions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
