import re
from difflib import SequenceMatcher
import config

def check_matching_domains(sender_domain: str, email_msg: dict, description: list, threshold: float = 0.8) -> int:
    """
    Check if the sender and receiver domains are similar but not identical based on string similarity.
    :return: Spam score
    """
    recipient_email = email_msg.get("Delivered-To") or email_msg.get("To")

    if recipient_email:
        # Extract the first recipient if multiple are present
        recipient_email = recipient_email.split(",")[0].strip()
        
        match = re.search(r'@([\w.-]+)', recipient_email)
        if match:
            receiver_domain = match.group(1)

            # Compute domain similarity
            similarity = SequenceMatcher(None, sender_domain, receiver_domain).ratio()

            if threshold < similarity < 1.0: 
                description.append(f"Sender domain '{sender_domain}' is suspiciously similar to recipient domain '{receiver_domain}'.")
                return config.DOMAIN_SIMILARITY_SCORE 

    return config.DOMAIN_NON_SIMILARITY_SCORE  
