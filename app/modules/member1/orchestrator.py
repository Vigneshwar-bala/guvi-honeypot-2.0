from app.core.session_store import get_or_create_session, update_session
from app.core.callback import send_final_callback

from app.modules.member2.scam_detection import detect_scam, calculate_sophistication
from app.modules.member2.tactic_classifier import classify_tactic
from app.modules.ai_agent.openrouter_engine import get_openrouter_engine

def process_message(payload):
    """Main orchestrator for processing incoming messages"""
    
    session = get_or_create_session(payload.sessionId)
    
    timestamp = getattr(payload.message, 'timestamp', None)
    update_session(session, payload.message.sender, payload.message.text, timestamp)
    
    scam_result = detect_scam(session, payload.message.text)
    session["confidence"] = scam_result.get("confidence", 0.0)
    
    tactic_result = classify_tactic(session, payload.message.text)
    
    session["extractedIntelligence"]["sophisticationLevel"] = calculate_sophistication(session)
    
    # Initialize OpenRouter engine
    openrouter_engine = get_openrouter_engine()

    # Prepare conversation history from session
    conversation_history = session.get("conversationHistory", [])

    # Prepare metadata
    metadata = {
        "channel": session.get("metadata", {}).get("channel", "SMS"),
        "language": session.get("metadata", {}).get("language", "English"),
        "locale": session.get("metadata", {}).get("locale", "IN"),
        "turn_count": session.get("turnCount", 0)
    }

    # Generate response using OpenRouter
    reply = openrouter_engine.generate_response(
        conversation_history=conversation_history,
        latest_message=payload.message.text,
        metadata=metadata
    )

    # Create response object matching expected format
    ai_response = {
        "reply": reply,
        "should_exit": False,  # Set based on your logic
        "reasoning": ""  # Set based on your logic
    }
    
    is_already_sent = session["flags"].get("callbackSent", False)
    should_exit = not is_already_sent and ai_response["should_exit"]
    
    if should_exit:
        print(f"[Session {payload.sessionId}] Exit triggered: {ai_response['reasoning']}")
        success = send_final_callback(session)
        if success:
            session["flags"]["callbackSent"] = True
    
    return {
        "status": "success",
        "reply": reply
    }
