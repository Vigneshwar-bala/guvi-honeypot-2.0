import os
import httpx

CALLBACK_URL = os.getenv("GUVI_CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
TIMEOUT = int(os.getenv("CALLBACK_TIMEOUT", "5"))

def generate_agent_summary(session: dict) -> str:
    """Generate insightful agent notes from conversation"""
    intel = session["extractedIntelligence"]
    turn_count = session["turnCount"]
    
    notes_parts = []
    
    # Scammer tactics
    tactics = intel.get("tacticPatterns", [])
    if "high_urgency_tactics" in tactics:
        notes_parts.append("employed high-pressure urgency tactics")
    if "legal_threat_tactics" in tactics:
        notes_parts.append("used legal intimidation")
    if "authority_impersonation" in tactics:
        notes_parts.append("impersonated authority figure")
    
    # Impersonation type
    impersonations = intel.get("impersonationClaims", [])
    if impersonations:
        notes_parts.append(f"claimed to be: {', '.join(impersonations)}")
    
    # Scam type
    scam_type = intel.get("scamType", "unknown")
    if scam_type != "unknown":
        notes_parts.append(f"classified as {scam_type}")
    
    # Intelligence quality
    info_count = sum(len(v) for k, v in intel.items() if isinstance(v, list) and k not in ["tacticPatterns", "organizationalClues", "impersonationClaims"])
    notes_parts.append(f"extracted {info_count} intelligence pieces")
    
    # Engagement quality
    if turn_count >= 15:
        notes_parts.append("sustained extended engagement")
    elif turn_count >= 8:
        notes_parts.append("achieved moderate engagement depth")
    
    # Sophistication
    sophistication = intel.get("sophisticationLevel", "unknown")
    if sophistication != "unknown":
        notes_parts.append(f"scammer sophistication: {sophistication}")
    
    if not notes_parts:
        return "Automated agentic engagement completed"
    
    return "; ".join(notes_parts).capitalize() + "."

def send_final_callback(session: dict):
    """Send final intelligence report to GUVI"""
    agent_notes = generate_agent_summary(session)
    
    payload = {
        "sessionId": session["sessionId"],
        "scamDetected": True,
        "totalMessagesExchanged": session["turnCount"],
        "extractedIntelligence": session["extractedIntelligence"],
        "agentNotes": agent_notes
    }

    print(f"📡 SENDING CALLBACK PAYLOAD: {payload['sessionId']}")
    # print(json.dumps(payload, indent=2)) # Uncomment this if you want to see the full JSON in logs

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.post(CALLBACK_URL, json=payload)
            print(f"✓ Callback sent for session {session['sessionId']}: HTTP {response.status_code}")
            try:
                print(f"📥 GUVI Server Response: {response.json()}")
            except:
                print(f"📥 GUVI Server Response: {response.text}")
            return True
    except Exception as e:
        print(f"✗ Callback failed for session {session['sessionId']}: {e}")
        return False
