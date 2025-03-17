from fastapi import FastAPI, Request
import spf
import email
from email import policy
from email.parser import BytesParser
import re

app = FastAPI()

def extract_sender_ip(headers: dict) -> str:
    """Extracts sender IP from the last 'Received' header."""
    received_headers = headers.get_all('Received', [])
    if received_headers:
        for header in headers[::-1]:  # Reverse iteration to get the last "from" header first
            match = re.search(r'from .* \[(\d+\.\d+\.\d+\.\d+)\]', header)
            if match:
                client_ip = match.group(1)
                return client_ip
    return None

def extract_return_path(headers: dict) -> str:
    """Extracts the Return-Path domain."""
    return_path = headers.get('Return-Path', '').strip('<>')
    if return_path:
        domain = return_path.split('@')[-1]
        return domain if domain else None
    return None

@app.post("/check-email")
async def process_email(request: Request):
    try:
        raw_email = await request.body()
        parsed_email = BytesParser(policy=policy.default).parsebytes(raw_email)
        headers = parsed_email
        
        sender_ip = extract_sender_ip(headers)
        return_path_domain = extract_return_path(headers)
        
        print(f'return patth: {return_path_domain}, sender_ip: {sender_ip}')

        if not sender_ip or not return_path_domain:
            return {"error": "Missing required headers (Received or Return-Path)"}
        
        # Perform SPF check
        spf_result, explanation = spf.check2(sender_ip, return_path_domain, return_path_domain)
        
        return {
            "sender_ip": sender_ip,
            "return_path_domain": return_path_domain,
            "spf_result": spf_result,
            "explanation": explanation
        }
    except Exception as e:
        print(f"error: {str(e)}")
        return {"error": str(e)}
