from fastapi import APIRouter, HTTPException, Request
from app.api.routes.check_email_headers import check_spf, check_dkim
import email
from email import policy
from email.utils import parseaddr
import re

router = APIRouter()

# Define spam threshold
SPAM_THRESHOLD = -5

@router.post("/check_email", response_model=dict)
async def process_email(request: Request):
    try:
        raw_email = await request.body()
        raw_email = raw_email.decode("utf-8", errors="ignore")
        parsed_email = email.message_from_string(raw_email, policy=policy.default)
        
        # Extract headers
        headers = dict(parsed_email.items())
        # Extract relevant SPF, DKIM, and DMARC fields
        mail_from = headers.get("Return-Path", "").strip("<>")  # Strip angle brackets
        received_spf = headers.get("Received-SPF", "")
        # Extract sender domain
        from_email = headers.get("From", "")
        _, sender_email = parseaddr(from_email)
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

        # Run SPF check
        spf_pass = False
        ip_match = re.search(r"client-ip=([\d\.]+)", received_spf)
        if ip_match:
            client_ip = ip_match.group(1)
            spf_pass = check_spf(mail_from, client_ip, sender_domain)
        
        # Scoring system
        score = 0
        description = []

        if not spf_pass:
            return {"spam": "spam", "score": score, "description": ["spf failed"]}  # Directly mark as spam if SPF fails
        
        dkim_pass = check_dkim(raw_email)

        if not dkim_pass:
            score -= 1
            description.append("dkim failed")

        is_spam = "spam" if score < SPAM_THRESHOLD else "ham"

        return {
            "spam": is_spam,
            "score": score,
            "description": description
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing email: {str(e)}")