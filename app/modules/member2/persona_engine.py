def generate_reply(session: dict, message: str) -> str:
    """
    Returns: Natural language human-like reply
    """
    # Use key from session_store.py (matches turnCount in SessionStore)
    turn = session.get("turnCount", 0)
    intelligence = session.get("extractedIntelligence", {})
    msg_lower = message.lower()
    
    # Signaling
    if "flags" not in session:
        session["flags"] = {}
    
    # Check if we have enough info to signal callback
    info_count = sum(len(v) for v in intelligence.values()) if isinstance(intelligence, dict) else 0
    if info_count >= 3 or turn >= 5:
        session["flags"]["readyForCallback"] = True

    # Turn-based persona logic
    if turn == 0:
        return "Hi, who's this? I'm in the middle of a lighting setup for a show."
    
    if "kyc" in msg_lower or "bank" in msg_lower:
        return "Wait, my bank account is at risk? I don't really understand these technical things. Can you help me step by step?"
    
    if "money" in msg_lower or "win" in msg_lower or "prize" in msg_lower:
        return "Did I really win? That would be amazing! I need funds for my next stage production. How do I claim it?"
    
    if "@" in msg_lower or "upi" in msg_lower:
        return "I tried the ID you sent but it didn't work. Is there a specific app I should use?"

    # Fallbacks
    responses = [
        "Are you still there? I'm trying to follow but I'm a bit slow with this.",
        "Can you explain that again? I want to make sure I don't do anything wrong.",
        "Should I tell my brother about this? He handles my finances usually.",
        "I'm really worried about my account. Please tell me what to do next."
    ]
    return responses[turn % len(responses)]
