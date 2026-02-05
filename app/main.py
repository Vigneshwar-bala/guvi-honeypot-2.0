from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
import traceback
from datetime import datetime

from app.schemas.request_response import RequestPayload, HoneypotResponse
from app.core.session_store import get_or_create_session, update_session
from app.modules.member2.scam_detection import detect_scam, calculate_sophistication
from app.modules.ai_agent.enhanced_agent import EnhancedAgent
from app.core.callback import send_final_callback

# Load environment variables
load_dotenv()

# Get API key from environment
API_KEY = os.getenv("API_KEY", "guvi-honeypot-demo-key")

# Initialize FastAPI app with enhanced configuration
app = FastAPI(
    title="Advanced Agentic Scam Honeypot",
    version="2.0.0",
    description="AI-powered honeypot with intelligent scam detection, multi-turn engagement, and intelligence extraction",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for production deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize enhanced agent
enhanced_agent = None

def get_enhanced_agent():
    """Lazy initialization of enhanced agent"""
    global enhanced_agent
    if enhanced_agent is None:
        enhanced_agent = EnhancedAgent()
    return enhanced_agent


@app.get("/")
def health():
    """Health check endpoint with system status"""
    return {
        "status": "ok",
        "service": "Advanced Agentic Scam Honeypot",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "features": [
            "scam_detection",
            "intelligence_extraction",
            "multi_turn_conversation",
            "adaptive_persona",
            "automatic_callback"
        ]
    }


@app.get("/stats")
def get_stats():
    """Get honeypot statistics"""
    from app.core.session_store import get_all_sessions
    sessions = get_all_sessions()
    
    total_sessions = len(sessions)
    scam_sessions = sum(1 for s in sessions.values() if s.get("confidence", 0) > 0.3)
    total_messages = sum(s.get("turnCount", 0) for s in sessions.values())
    
    # Intelligence stats
    total_upis = sum(len(s["extractedIntelligence"].get("upiIds", [])) for s in sessions.values())
    total_banks = sum(len(s["extractedIntelligence"].get("bankAccounts", [])) for s in sessions.values())
    total_links = sum(len(s["extractedIntelligence"].get("phishingLinks", [])) for s in sessions.values())
    total_phones = sum(len(s["extractedIntelligence"].get("phoneNumbers", [])) for s in sessions.values())
    
    return {
        "total_sessions": total_sessions,
        "scam_sessions_detected": scam_sessions,
        "total_messages_exchanged": total_messages,
        "intelligence_extracted": {
            "upi_ids": total_upis,
            "bank_accounts": total_banks,
            "phishing_links": total_links,
            "phone_numbers": total_phones
        }
    }


@app.post("/honeypot/message", response_model=HoneypotResponse)
async def honeypot_message(request: RequestPayload, x_api_key: str = Header(None)):
    """
    🎯 MAIN HONEYPOT ENDPOINT
    
    Handles incoming scam messages with:
    - Scam detection and intent analysis
    - Intelligent multi-turn conversation
    - Automated intelligence extraction
    - Session state management
    - Automatic callback on scam confirmation
    
    Args:
        request: RequestPayload containing message, conversation history, and metadata
        x_api_key: API key for authentication (header parameter)
    
    Returns:
        HoneypotResponse: JSON response with status and AI-generated reply
    """

    print("\n" + "="*100)
    print(f"🔔 INCOMING REQUEST | Session: {request.sessionId} | Time: {datetime.utcnow().isoformat()}")
    print("="*100)

    # ============================================
    # STEP 1: AUTHENTICATION
    # ============================================
    if x_api_key != API_KEY:
        print(f"❌ Authentication failed: Invalid API key")
        raise HTTPException(status_code=401, detail="Invalid API key")
    print("✅ Authentication successful")

    try:
        # ============================================
        # STEP 2: SESSION MANAGEMENT
        # ============================================
        session = get_or_create_session(request.sessionId)
        print(f"📊 Session loaded | Turn: {session['turnCount']} | Confidence: {session.get('confidence', 0):.2f}")

        # Update session with incoming message
        update_session(
            session,
            sender=request.message.sender,
            text=request.message.text,
            timestamp=request.message.timestamp
        )

        # ============================================
        # STEP 3: SCAM DETECTION & INTELLIGENCE EXTRACTION
        # ============================================
        print(f"🔍 Analyzing message: '{request.message.text[:100]}...'")
        
        detection_result = detect_scam(session, request.message.text)
        session["confidence"] = detection_result["confidence"]
        
        scam_detected = detection_result["scamDetected"]
        confidence = detection_result["confidence"]
        signals = detection_result.get("signals", [])
        
        print(f"🎯 Scam Detection: {'✅ SCAM DETECTED' if scam_detected else '⚠️  Suspicious'}")
        print(f"📈 Confidence Score: {confidence:.2f}")
        if signals:
            print(f"🚨 Signals Detected: {', '.join(signals[:5])}")
        
        # Update sophistication level
        session["extractedIntelligence"]["sophisticationLevel"] = calculate_sophistication(session)
        
        # ============================================
        # STEP 4: AI AGENT RESPONSE GENERATION
        # ============================================
        print("🤖 Generating AI response...")
        
        # Prepare conversation context
        conversation_history = request.conversationHistory or []
        latest_message = request.message.text
        
        # Extract metadata
        metadata_dict = {}
        if hasattr(request.metadata, '__dict__'):
            metadata_dict = request.metadata.__dict__
        elif isinstance(request.metadata, dict):
            metadata_dict = request.metadata
        
        # Get enhanced agent
        agent = get_enhanced_agent()
        
        # Generate context-aware response
        reply = agent.generate_response(
            session=session,
            conversation_history=conversation_history,
            latest_message=latest_message,
            metadata=metadata_dict,
            scam_detected=scam_detected,
            confidence=confidence
        )
        
        print(f"💬 AI Response: '{reply[:100]}...'")
        
        # ============================================
        # STEP 5: UPDATE SESSION WITH AGENT RESPONSE
        # ============================================
        update_session(
            session,
            sender="user",  # Our AI agent pretending to be user
            text=reply,
            timestamp=int(datetime.utcnow().timestamp() * 1000)
        )
        
        # ============================================
        # STEP 6: TRIGGER CALLBACK IF CRITERIA MET
        # ============================================
        # Callback criteria:
        # - Scam detected with high confidence (>0.5)
        # - Multiple turns (>5) for sufficient intelligence
        # - OR Very high confidence (>0.8) regardless of turns
        
        should_callback = False
        callback_reason = ""
        
        if confidence > 0.8 and session["turnCount"] >= 3:
            should_callback = True
            callback_reason = "High confidence + minimum engagement"
        elif confidence > 0.5 and session["turnCount"] >= 8:
            should_callback = True
            callback_reason = "Good confidence + sufficient intelligence"
        elif session["turnCount"] >= 15:
            should_callback = True
            callback_reason = "Extended engagement threshold reached"
        
        if should_callback and not session.get("callback_sent", False):
            print(f"\n🔔 TRIGGERING CALLBACK | Reason: {callback_reason}")
            print(f"📊 Final Stats: {session['turnCount']} turns, {confidence:.2f} confidence")
            
            callback_success = send_final_callback(session)
            if callback_success:
                session["callback_sent"] = True
                print("✅ Callback sent successfully")
            else:
                print("❌ Callback failed - will retry")
        
        # ============================================
        # STEP 7: RETURN RESPONSE
        # ============================================
        response_data = HoneypotResponse(status="success", reply=reply)
        
        print("\n" + "="*100)
        print(f"✅ REQUEST COMPLETED | Session: {request.sessionId}")
        print(f"📊 Intelligence: UPI={len(session['extractedIntelligence']['upiIds'])}, "
              f"Banks={len(session['extractedIntelligence']['bankAccounts'])}, "
              f"Links={len(session['extractedIntelligence']['phishingLinks'])}")
        print("="*100 + "\n")
        
        return response_data

    except HTTPException as he:
        # Re-raise HTTP exceptions
        raise he
    
    except Exception as e:
        print(f"\n❌ CRITICAL ERROR OCCURRED")
        print(f"Exception type: {type(e).__name__}")
        print(f"Exception message: {str(e)}")
        print(f"Full traceback:")
        traceback.print_exc()
        print("="*100 + "\n")
        
        # Return fallback response instead of error
        fallback_reply = "I'm not sure I understand. Could you please clarify?"
        return HoneypotResponse(status="success", reply=fallback_reply)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper JSON response"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    print(f"[GLOBAL EXCEPTION HANDLER] Unexpected error: {str(exc)}")
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)