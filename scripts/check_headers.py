import spf
import dns.resolver
import dkim
from email import message_from_string
from dns.resolver import resolve, NXDOMAIN, NoAnswer, Timeout
import config


def check_spf(headers, sender_ip, helo_domain, return_path, description):
    """Check SPF record validation and assign score"""
    try:
        spf_result, explanation = spf.query(sender_ip, helo_domain, return_path)[:2]
        if spf_result == "pass":
            return config.SPF_PASS_SCORE
        else:
            description.append(f"SPF failed: {spf_result} - {explanation}")
            return config.SPF_FAIL_SCORE
    except Exception as e:
        description.append(f"SPF check error: {str(e)}")
        return config.SPF_FAIL_SCORE


def check_dkim(raw_email, description):
    """Check DKIM signature validation and assign score"""
    try:
        if dkim.verify(raw_email.encode()):  # Verify DKIM using the full email
            return config.DKIM_PASS_SCORE
        description.append("DKIM failed or missing")
        return config.DKIM_FAIL_SCORE
    except Exception as e:
        description.append(f"DKIM check error: {str(e)}")
        return config.DKIM_FAIL_SCORE


def check_dmarc(return_path, description):
    """Check DMARC policy compliance and assign score"""
    try:
        domain = return_path.split('@')[-1]
        dmarc_record = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_record, "TXT")
        for rdata in answers:
            if "p=reject" in str(rdata) or "p=quarantine" in str(rdata):
                return config.DMARC_PASS_SCORE
        description.append("DMARC failed or missing")
        return config.DMARC_FAIL_SCORE  # Fixed typo
    except (NXDOMAIN, NoAnswer, Timeout):
        description.append("DMARC record not found")
        return config.DMARC_FAIL_SCORE  # Fixed typo
    except Exception as e:
        description.append(f"DMARC check error: {str(e)}")
        return config.DMARC_FAIL_SCORE  # Fixed typo


def check_rbl(sender_ip, description):
    """Check if sender IP is listed in RBL and assign score"""
    blacklists = [
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "bl.spamcop.net",
        "blacklist.woody.ch"
    ]
    
    try:
        # Convert IP into RBL query format (reverse octets)
        reversed_ip = ".".join(sender_ip.split(".")[::-1])
        for bl in blacklists:
            query = f"{reversed_ip}.{bl}"
            dns.resolver.resolve(query, "A")
            description.append(f"Sender IP {sender_ip} is blacklisted in {bl}")
            return config.RBL_FAIL_SCORE
    except (NXDOMAIN, NoAnswer, Timeout):
        pass  # IP is not blacklisted
    
    return config.RBL_PASS_SCORE



def check_headers(raw_email, helo_domain, sender_ip, return_path, description):
    """Check SPF, DKIM, DMARC, RBL, and scan URLs"""
    email_msg = message_from_string(raw_email)
    headers = {key: value for key, value in email_msg.items()}
    
    # Initialize score
    score = 0

    # Run individual checks
    score += check_spf(headers, sender_ip, helo_domain, return_path, description)
    score += check_dkim(raw_email, description) 
    score += check_dmarc(return_path, description)
    score += check_rbl(sender_ip, description) 

    return score
