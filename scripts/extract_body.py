import re
from email.message import Message
from bs4 import BeautifulSoup

def extract_email_body(email_msg: Message, description: list):
    """
    Extracts the visible email content (text & HTML) and assigns a body_score based on suspicious attachments.
    """
    body_parts = []
    body_score = 0  # Initialize spam score for body
    suspicious_extensions = {".exe", ".scr", ".zip", ".rar", ".js", ".vbs", ".bat", ".cmd", ".dll"}

    # Check if email has attachments
    has_attachment = False

    if email_msg.is_multipart():
        for part in email_msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "").lower()

            # Detect suspicious attachments
            if "attachment" in content_disposition:
                has_attachment = True
                filename = part.get_filename()
                if filename:
                    ext = "." + filename.split(".")[-1].lower()
                    if ext in suspicious_extensions:
                        body_score += 5  # Increase score for suspicious files
            
            # Extract readable body content (text or HTML)
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset("utf-8")
                    decoded_text = payload.decode(charset, errors="ignore")

                    if content_type == "text/plain":
                        body_parts.append(decoded_text)
                    elif content_type == "text/html":
                        soup = BeautifulSoup(decoded_text, "html.parser")
                        visible_text = soup.get_text(separator="\n", strip=True)
                        body_parts.append(visible_text)
            except Exception:
                continue
    else:
        # If email is not multipart, extract content directly
        try:
            payload = email_msg.get_payload(decode=True)
            if payload:
                charset = email_msg.get_content_charset("utf-8")
                body_parts.append(payload.decode(charset, errors="ignore"))
        except Exception:
            pass

    # Extract Subject
    subject = email_msg.get("Subject", "")
    if subject:
        body_parts.insert(0, f"Subject: {subject}")

    # Final clean email content (what you'd see in Gmail)
    visible_body_content = "\n".join(body_parts)

    # If email contains an attachment, increase score
    if has_attachment:
        body_score += 2  # Small penalty for having attachments in general

    return visible_body_content, body_score
