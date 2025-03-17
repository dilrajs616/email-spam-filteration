from fastapi import APIRouter
from pydantic import BaseModel
import email
from app.api.routes.check_email_headers import check_spf, check_dkim, check_dmarc

class EmailRequest(BaseModel):
    raw_email: str

router = APIRouter()

@router.get("/")
async def get_emails():
    return {"message": "List of emails"}


@router.post("/check_email")
def check_email(email_request: EmailRequest):
    raw_email = email_request.raw_email
    msg = email.message_from_string(raw_email)

    mailfrom = msg.get("Return-Path", "").strip("<>")
    helo = msg.get("Received", "").split()[-1] if "Received" in msg else "unknown"
    ip = "127.0.0.1"  # Placeholder (Extract actual sending IP from headers)
    domain = mailfrom.split('@')[-1] if '@' in mailfrom else None

    if not domain:
        return {"status": "spam", "reason": "Missing sender domain"}

    spf_pass = check_spf(mailfrom, ip, helo)
    dkim_pass = check_dkim(raw_email)
    dmarc_pass = check_dmarc(domain)

    if not (spf_pass and dkim_pass and dmarc_pass):
        return {"status": "spam", "reason": "Failed SPF, DKIM, or DMARC"}

    return {"status": "ham", "reason": "Passed authentication"}
