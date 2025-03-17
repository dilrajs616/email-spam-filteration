import dkim
import spf
import dns.resolver

def check_spf(mailfrom, ip, helo):
    response = spf.check2(ip, mailfrom, helo)
    print("SPF Check Response:", response)  # Debugging
    return response

def check_dkim(raw_email):
    try:
        return dkim.verify(raw_email.encode())
    except Exception:
        return False

def check_dmarc(domain):
    try:
        txt_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in txt_records:
            if 'p=' in record.to_text():
                return True
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    return False