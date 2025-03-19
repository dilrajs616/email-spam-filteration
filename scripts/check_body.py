import re
import config
import requests
from email.message import Message
from bs4 import BeautifulSoup

def extract_urls_from_email(email_msg):
    urls = set()  # Use a set to avoid duplicates

    # Handle multipart emails
    if email_msg.is_multipart():
        for part in email_msg.walk():
            content_type = part.get_content_type()
            try:
                text_content = part.get_payload(decode=True).decode(errors="ignore")
                urls.update(re.findall(r'https?://\S+', text_content))
                if content_type == "text/html":
                    soup = BeautifulSoup(text_content, "html.parser")
                    urls.update(link["href"] for link in soup.find_all("a", href=True))
            except Exception:
                continue  # Ignore decoding errors
    else:
        # Single-part email
        text_content = email_msg.get_payload(decode=True).decode(errors="ignore")
        urls.update(re.findall(r'https?://\S+', text_content))

    return list(urls)



def check_urls_with_safebrowsing(urls, description):
    """Check URLs against Google Safe Browsing API."""
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={config.SAFEBROWSING_API_KEY}"
    body = {
        "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls]
        }
    }
    
    try:
        response = requests.post(safe_browsing_url, json=body)
        response_data = response.json()
        if response.status_code == 200 and "matches" in response_data:
            description.append("Unsafe URLs detected by Google Safe Browsing API")
            return config.SAFEBROWSING_FAIL_SCORE
    except Exception as e:
        description.append(f"Safe Browsing check error: {str(e)}")
    
    return config.SAFEBROWSING_PASS_SCORE

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
    urls = extract_urls_from_email(email_msg)
    score += check_urls_with_safebrowsing(urls, description)
    score += check_suspicious_attachments(email_msg, description)

    return score
