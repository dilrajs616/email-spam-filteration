import spf  # SPF validation library
import email
import re
from email import policy
from email.utils import parseaddr

def parse_email_headers(raw_email:str) -> dict:
    """ Parses email headers and extracts necessary information """
    parsed_email = email.message_from_string(raw_email, policy=policy.default)
    headers = dict(parsed_email.items())

    # Extract Return-Path (MAIL FROM in SPF check)
    mail_from = headers.get("Return-Path", "").strip("<>") or None

    # Extract sender domain from From header
    from_email = headers.get("From", "")
    _, sender_email = parseaddr(from_email)
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else None

    # Extract HELO/EHLO domain and Client IP from Received headers
    received_headers = parsed_email.get_all("Received", [])  # Correct way

    client_ip = None
    helo_domain = None

    for received in received_headers:
        # Match IP address
        ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", received)
        if ip_match:
            client_ip = ip_match.group(1)

        # Match HELO domain
        helo_match = re.search(r"helo=([\w\.-]+)", received, re.IGNORECASE)
        if helo_match:
            helo_domain = helo_match.group(1)

        # Stop at first valid entry (Received headers are ordered from latest to oldest)
        if client_ip and helo_domain:
            break

    return {
        "mail_from": mail_from,
        "sender_domain": sender_domain,
        "client_ip": client_ip,
        "helo_domain": helo_domain
    }

def check_spf(mailfrom, ip, helo):
    """ Performs SPF validation and returns True if SPF passes, False otherwise """
    if not mailfrom or not ip or not helo:
        print("SPF Check Skipped: Missing parameters")
        return False  # Default to fail if any required parameter is missing

    response = spf.check2(ip, mailfrom, helo)
    print("SPF Check Response:", response)  # Debugging

    return response[0] == "pass"  # Return True if SPF check passes, else False
