import dkim
import spf
import dns.resolver

def check_spf(mailfrom, ip, helo):
    response = spf.check2(ip, mailfrom, helo)
    print("SPF Check Response:", response)  
    return response[0]

def check_dkim(raw_email):
    try:
        return dkim.verify(raw_email.encode())
    except Exception:
        return False