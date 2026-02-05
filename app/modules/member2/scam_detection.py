import re

def detect_scam(session: dict, message: str) -> dict:
    """
    Detect scam intent and extract intelligence
    Returns: {"scamDetected": bool, "confidence": float, "signals": list}
    """
    intel = session.get("extractedIntelligence", {})
    signals = []
    confidence = session.get("confidence", 0.0)
    msg_lower = message.lower()

    # Extract UPI IDs
    upis = re.findall(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', message)
    for upi in upis:
        if upi not in intel["upiIds"]:
            intel["upiIds"].append(upi)
            signals.append(f"UPI detected: {upi}")
            confidence += 0.3

    # Extract bank accounts
    banks = re.findall(r'\b\d{9,18}\b', message)
    for bank in banks:
        if bank not in intel["bankAccounts"]:
            intel["bankAccounts"].append(bank)
            signals.append("Bank account detected")
            confidence += 0.2

    # Extract URLs
    urls = re.findall(r'https?://\S+', message)
    for url in urls:
        if url not in intel["phishingLinks"]:
            intel["phishingLinks"].append(url)
            signals.append(f"URL detected: {url}")
            confidence += 0.3

    # Extract phone numbers
    phones = re.findall(r'\b\d{10,12}\b', message)
    for phone in phones:
        if phone not in intel["phoneNumbers"]:
            intel["phoneNumbers"].append(phone)
            signals.append(f"Phone detected: {phone}")
            confidence += 0.1

    # Scam keywords
    keywords = {
        "kyc": 0.4, "lottery": 0.5, "urgent": 0.3, "block": 0.3, 
        "win": 0.4, "otp": 0.5, "verify": 0.3, "account": 0.2,
        "suspend": 0.4, "prize": 0.5, "congratulations": 0.4,
        "tax": 0.3, "refund": 0.4, "legal": 0.3, "court": 0.4
    }
    for kw, weight in keywords.items():
        if kw in msg_lower:
            if kw not in intel["suspiciousKeywords"]:
                intel["suspiciousKeywords"].append(kw)
            signals.append(f"Keyword: {kw}")
            confidence += weight

    # Detect tactics
    if any(w in msg_lower for w in ["urgent", "immediately", "now", "today only", "within 24"]):
        if "high_urgency_tactics" not in intel["tacticPatterns"]:
            intel["tacticPatterns"].append("high_urgency_tactics")
            
    if any(w in msg_lower for w in ["legal action", "arrest", "case", "court", "police"]):
        if "legal_threat_tactics" not in intel["tacticPatterns"]:
            intel["tacticPatterns"].append("legal_threat_tactics")
            
    if any(w in msg_lower for w in ["bank", "official", "department", "government"]):
        if "authority_impersonation" not in intel["tacticPatterns"]:
            intel["tacticPatterns"].append("authority_impersonation")

    # Detect impersonation claims
    if any(bank in msg_lower for bank in ["sbi", "hdfc", "icici", "axis", "bank of", "reserve bank"]):
        if "bank_official" not in intel["impersonationClaims"]:
            intel["impersonationClaims"].append("bank_official")
    
    if any(gov in msg_lower for gov in ["income tax", "gst", "government", "ministry", "customs"]):
        if "government_official" not in intel["impersonationClaims"]:
            intel["impersonationClaims"].append("government_official")
    
    if any(w in msg_lower for w in ["lottery", "prize", "winner", "lucky draw"]):
        if "lottery_organizer" not in intel["impersonationClaims"]:
            intel["impersonationClaims"].append("lottery_organizer")

    # Organizational clues
    org_keywords = ["team", "senior", "manager", "department", "colleague", "supervisor", "head office"]
    for keyword in org_keywords:
        if keyword in msg_lower and keyword not in intel["organizationalClues"]:
            intel["organizationalClues"].append(f"mentioned_{keyword}")

    # Classify scam type
    if intel.get("scamType") == "unknown":
        if any(w in msg_lower for w in ["upi", "paytm", "phonepe", "gpay"]):
            intel["scamType"] = "UPI_fraud"
        elif any(w in msg_lower for w in ["kyc", "account", "bank"]):
            intel["scamType"] = "banking_fraud"
        elif any(w in msg_lower for w in ["lottery", "prize", "won", "winner"]):
            intel["scamType"] = "lottery_scam"
        elif any(w in msg_lower for w in ["otp", "verification", "code"]):
            intel["scamType"] = "OTP_fraud"
        elif urls:
            intel["scamType"] = "phishing"

    confidence = min(1.0, confidence)
    
    return {
        "scamDetected": confidence > 0.3,
        "detected": confidence > 0.3,
        "confidence": round(confidence, 2),
        "signals": list(set(signals))
    }

def calculate_sophistication(session: dict) -> str:
    """Calculate scammer sophistication level"""
    intel = session["extractedIntelligence"]
    history = session.get("conversationHistory", [])
    
    score = 0
    
    # Message complexity
    scammer_msgs = [msg["text"] for msg in history if msg.get("sender") == "scammer"]
    if scammer_msgs:
        avg_length = sum(len(m.split()) for m in scammer_msgs) / len(scammer_msgs)
        if avg_length > 20:
            score += 3
        elif avg_length > 10:
            score += 1
    
    # Multiple intelligence types
    intel_types = sum(1 for k, v in intel.items() if isinstance(v, list) and len(v) > 0 and k not in ["tacticPatterns", "organizationalClues", "impersonationClaims"])
    score += intel_types
    
    # Organizational mentions
    if len(intel.get("organizationalClues", [])) > 0:
        score += 2
    
    # Multiple tactics
    if len(intel.get("tacticPatterns", [])) >= 2:
        score += 2
    
    # Persistence
    if session.get("turnCount", 0) > 12:
        score += 2
    
    if score >= 8:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"
