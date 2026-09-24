def classify_intent(s):
    evidence=[]
    if s.get("password_fields"): evidence.append("Password field")
    if s.get("cross_domain_form"): evidence.append("Cross-domain form action")
    if s.get("card_fields") or s.get("otp_fields"): evidence.append("Card/OTP fields")
    if s.get("identity_fields"): evidence.append("Identity fields")
    if s.get("suspicious_downloads"): evidence.append("Risky download links")
    if s.get("remote_lure"): evidence.append("Remote-access lure")
    if s.get("card_fields") or s.get("otp_fields"): purpose="FINANCIAL INFORMATION / PAYMENT FRAUD"
    elif s.get("password_fields"): purpose="CREDENTIAL / PASSWORD HARVESTING"
    elif s.get("identity_fields"): purpose="IDENTITY INFORMATION COLLECTION"
    elif s.get("suspicious_downloads"): purpose="MALWARE DELIVERY / UNSAFE DOWNLOAD LURE"
    elif s.get("remote_lure"): purpose="DEVICE-ACCESS / REMOTE-CONTROL LURE"
    else: purpose="UNKNOWN / INSUFFICIENT EVIDENCE"
    return {"likely_purpose":purpose,"evidence":evidence}
