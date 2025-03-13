from flask import request, jsonify
import email
import spf
import dkim
import re
from authheaders import validate_headers

from app import app

@app.route("/spam-test", methods=["POST"])
def spam_test():
    data = request.form.get('email')  # Assuming raw email string is sent
    if not data:
        return jsonify({"error": "No email data provided"}), 400

    # Parse email
    msg = email.message_from_string(data)
    headers = dict(msg.items())
    received_headers = msg.get_all("Received", [])
    return_path = msg.get("Return-Path")

    # Extract sending IP from Received headers
    ip_match = re.search(r'\[?(\d+\.\d+\.\d+\.\d+)\]?', received_headers[-1]) if received_headers else None
    sending_ip = ip_match.group(1) if ip_match else None

    # Extract Envelope Sender
    envelope_sender = return_path.strip('<>') if return_path else None
    domain = envelope_sender.split('@')[-1] if envelope_sender else None

    results = {"SPF": None, "DKIM": None, "DMARC": None}

    # SPF Check
    if sending_ip and envelope_sender:
        spf_result, _, _ = spf.check2(sending_ip, domain, envelope_sender)
        results["SPF"] = spf_result

    # DKIM Check
    try:
        dkim_valid = dkim.verify(data.encode())
        results["DKIM"] = "pass" if dkim_valid else "fail"
    except:
        results["DKIM"] = "error"

    # DMARC Check
    try:
        dmarc_result = validate_headers(data.encode(), validators=['dmarc'])
        results["DMARC"] = "pass" if dmarc_result.dmarc else "fail"
    except:
        results["DMARC"] = "error"

    return jsonify(results)
