_sessions = {}

def get_or_create_session(session_id: str) -> dict:
    if session_id not in _sessions:
        _sessions[session_id] = {
            "sessionId": session_id,
            "turnCount": 0,
            "conversationHistory": [],
            "extractedIntelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
                "tacticPatterns": [],
                "organizationalClues": [],
                "impersonationClaims": [],
                "scamType": "unknown",
                "sophisticationLevel": "unknown"
            },
            "flags": {},
            "confidence": 0.0
        }
    return _sessions[session_id]

def update_session(session: dict, sender: str, text: str, timestamp: int = None):
    session["turnCount"] += 1
    message_obj = {"sender": sender, "text": text}
    if timestamp:
        message_obj["timestamp"] = timestamp
    session["conversationHistory"].append(message_obj)

def get_all_sessions() -> dict:
    return _sessions
