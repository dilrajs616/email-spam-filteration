import re
from bs4 import BeautifulSoup
import spf
import dns.resolver
import dkim
import requests
from email import message_from_string
from dns.resolver import resolve, NXDOMAIN, NoAnswer, Timeout

def extract_urls_from_email(email_msg):
    urls = set()  # Use a set to avoid duplicates
    
    # Extract URLs from plain text
    text_content = email_msg.get_payload(decode=True).decode(errors="ignore")
    urls.update(re.findall(r'https?://\S+', text_content))

    # Extract URLs from HTML (if available)
    if email_msg.get_content_type() == "text/html":
        soup = BeautifulSoup(text_content, "html.parser")
        for link in soup.find_all("a", href=True):
            urls.add(link["href"])
    
    return list(urls)

def check_spf(headers, sender_ip, helo_domain, return_path, description):
    """Check SPF record validation and assign score"""
    try:
        spf_result = spf.check2(sender_ip, helo_domain, return_path)
        if spf_result[0] == 'pass':
            return 0
        else:
            description.append(f"SPF failed: {spf_result[0]}")
            return 5
    except Exception as e:
        description.append(f"SPF check error: {str(e)}")
        return 5

def check_dkim(headers, description):
    """Check DKIM signature validation and assign score"""
    try:
        dkim_signature = headers.get("DKIM-Signature")
        if dkim_signature:
            raw_email = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
            if dkim.verify(raw_email.encode()):
                return 0
        description.append("DKIM failed or missing")
        return 5
    except Exception as e:
        description.append(f"DKIM check error: {str(e)}")
        return 5

def check_dmarc(headers, return_path, description):
    """Check DMARC policy compliance and assign score"""
    try:
        domain = return_path.split('@')[-1]
        dmarc_record = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_record, 'TXT')
        for rdata in answers:
            if "p=reject" in str(rdata) or "p=quarantine" in str(rdata):
                return 0
        description.append("DMARC failed or missing")
        return 5
    except (NXDOMAIN, NoAnswer, Timeout):
        description.append("DMARC record not found")
        return 5
    except Exception as e:
        description.append(f"DMARC check error: {str(e)}")
        return 5

def check_rbl(sender_domain, description):
    """Check if sender domain is listed in RBL and assign score"""
    blacklists = [
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "bl.spamcop.net",
        "blacklist.woody.ch"
    ]
    try:
        for bl in blacklists:
            query = f"{sender_domain}.{bl}"
            dns.resolver.resolve(query, "A")
            description.append(f"Sender domain is blacklisted in {bl}")
            return 10
    except (NXDOMAIN, NoAnswer, Timeout):
        pass
    return 0

def check_urls_with_safebrowsing(urls, api_key, description):
    """Check URLs against Google Safe Browsing API."""
    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key
    body = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls]
        }
    }
    response = requests.post(safe_browsing_url, json=body)
    if response.status_code == 200 and response.json():
        description.append("Unsafe URLs detected by Google Safe Browsing API")
        return 10
    return 0



def check_headers(raw_email, helo_domain, sender_ip, return_path, safebrowsing_api_key):
    '''Check SPF, DKIM, DMARC, RBL, and scan URLs & attachments'''
    email_msg = message_from_string(raw_email)
    headers = {key: value for key, value in email_msg.items()}
    description = []
    urls = extract_urls_from_email(raw_email)
    
    # Initialize score
    score = 0
    
    # Run individual checks
    score += check_spf(headers, sender_ip, helo_domain, return_path, description)
    score += check_dkim(headers, description)
    score += check_dmarc(headers, return_path, description)
    score += check_rbl(return_path.split('@')[-1], description)
    score += check_urls_with_safebrowsing(urls, safebrowsing_api_key, description)
    
    return {"score": score, "description": description}
