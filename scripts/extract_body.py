import re

# List of suspicious file extensions (can be expanded)
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".ps1", ".com"}

def check_email_body(email_msg, description):
    body_parts = []
    spam_score = 0

    if email_msg.is_multipart():
        for part in email_msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Check for attachments
            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename()
                if filename:
                    ext = filename.lower().split('.')[-1]  # Get file extension
                    ext = f".{ext}"  # Format it as ".exe"
                    if ext in SUSPICIOUS_EXTENSIONS:
                        spam_score += 10  # Increase spam score for suspicious attachment
                        description.append(f"Suspicious attachment detected: {filename}")

            # Extract text content
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset("utf-8")
                    body_parts.append(payload.decode(charset, errors="ignore"))
            except Exception:
                continue
    else:
        try:
            payload = email_msg.get_payload(decode=True)
            if payload:
                charset = email_msg.get_content_charset("utf-8")
                body_parts.append(payload.decode(charset, errors="ignore"))
        except Exception:
            pass

    body_text = "\n".join(body_parts)
    return body_text, spam_score
