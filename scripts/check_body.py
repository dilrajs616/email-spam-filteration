from email.message import Message

def check_suspicious_attachments(email_text: str, description: list):
    """
    Searches for suspicious file extensions in email text.
    Returns a spam score based on findings.
    """
    suspicious_extensions = [".exe ", ".scr ", ".zip ", ".rar ", ".js ", ".vbs ", ".bat ", ".cmd ", ".dll "]
    spam_score = 0

    for ext in suspicious_extensions:
        if ext in email_text.lower():  # Case-insensitive check
            spam_score += 5
            description.append(f"Suspicious file type detected: {ext.strip()}")

    return spam_score




def check_email_body(email_msg : Message, description: list) -> int:
    score = 0
    score += check_suspicious_attachments(email_msg, description)

    return score
