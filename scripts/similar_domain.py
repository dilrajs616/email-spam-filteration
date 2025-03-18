import re
from difflib import SequenceMatcher

def check_matching_domains(sender_domain: str, email_msg: str, description: list, threshold: float = 0.8) -> bool:
    """
    Check if the sender and receiver domains are similar based on string similarity.
    :return: True if domains are similar, False otherwise
    """
    recipient_email = email_msg["Delivered-To"] or email_msg["To"]
    if recipient_email:
        match = re.search(r'@([\w.-]+)', recipient_email)
        receiver_domain = match.group(1) 
    similarity = SequenceMatcher(None, sender_domain, receiver_domain).ratio()
    if similarity >= threshold:
        description.append("sender domain matching with receiver domain")
        return +5

