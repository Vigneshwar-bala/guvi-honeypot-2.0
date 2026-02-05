def classify_tactic(session: dict, message: str) -> dict:
    """
    Returns:
    {
        "activeTactics": list[str],
        "tacticIntensity": int
    }
    """
    msg_lower = message.lower()
    tactics = []
    
    if any(k in msg_lower for k in ["urgent", "now", "immediately"]):
        tactics.append("urgency")
    if any(k in msg_lower for k in ["bank", "official", "kyc"]):
        tactics.append("authority")
    if any(k in msg_lower for k in ["win", "prize", "money"]):
        tactics.append("financial_gain")
        
    intensity = 1 + msg_lower.count('!')
    
    # For Member 1 compatibility
    primary = tactics[0] if tactics else "unknown"
    
    return {
        "activeTactics": tactics,
        "tactic": primary,
        "tacticIntensity": min(10, intensity)
    }
