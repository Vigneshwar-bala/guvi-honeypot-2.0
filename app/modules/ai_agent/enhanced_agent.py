import os
from typing import List, Dict
from openai import OpenAI
import random

class EnhancedAgent:
    """
    Enhanced AI Agent with:
    - Adaptive persona based on scam type
    - Multi-turn conversation memory
    - Intelligence extraction prompting
    - Believable human-like responses
    - Self-correction capabilities
    """
    
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not found in environment variables")
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://openrouter.ai/api/v1",
        )
        
        # Persona templates for different scenarios
        self.personas = {
            "cautious_elderly": "Rajesh Kumar, a 62-year-old retired government employee, not very tech-savvy but careful with money",
            "busy_professional": "Priya Sharma, a 34-year-old working professional, busy but concerned about financial matters",
            "tech_novice": "Amit Patel, a 45-year-old small business owner, limited tech knowledge but eager to protect assets",
            "student": "Rohit Singh, a 22-year-old college student, somewhat tech-aware but inexperienced with scams"
        }
    
    def generate_response(
        self, 
        session: dict,
        conversation_history: List,
        latest_message: str,
        metadata: dict,
        scam_detected: bool,
        confidence: float
    ) -> str:
        """
        Generate intelligent, context-aware response
        
        Args:
            session: Session data with intelligence
            conversation_history: Previous messages
            latest_message: Current scammer message
            metadata: Channel, language, locale info
            scam_detected: Whether scam was detected
            confidence: Detection confidence score
        
        Returns:
            Human-like response string
        """
        try:
            print("\n[EnhancedAgent] Starting response generation...")
            
            # Build adaptive system prompt
            system_prompt = self._build_adaptive_prompt(
                session=session,
                metadata=metadata,
                scam_detected=scam_detected,
                confidence=confidence
            )
            
            # Build conversation messages
            messages = self._build_conversation_messages(
                conversation_history=conversation_history,
                latest_message=latest_message,
                system_prompt=system_prompt
            )
            
            print(f"[EnhancedAgent] System prompt length: {len(system_prompt)}")
            print(f"[EnhancedAgent] Message count: {len(messages)}")
            print(f"[EnhancedAgent] Calling OpenRouter API...")
            
            # Call LLM
            response = self.client.chat.completions.create(
                model="anthropic/claude-3-haiku",  # More reliable model
                messages=messages,
                temperature=0.8,  # Higher for more natural variation
                max_tokens=200,
                top_p=0.9
            )
            
            result = response.choices[0].message.content.strip()
            
            print(f"[EnhancedAgent] ✅ Response generated: {len(result)} chars")
            print(f"[EnhancedAgent] Preview: {result[:100]}...")
            
            if not result or len(result) < 5:
                print("[EnhancedAgent] ⚠️  Response too short, using fallback")
                return self._get_fallback_response(session, metadata)
            
            return result
        
        except Exception as e:
            print(f"[EnhancedAgent] ❌ Error: {type(e).__name__}: {str(e)}")
            print(f"[EnhancedAgent] ❌ API Key present: {'Yes' if self.api_key else 'No'}")
            print(f"[EnhancedAgent] ❌ Model used: anthropic/claude-3-haiku")
            print(f"[EnhancedAgent] ❌ Messages count: {len(messages)}")
            print(f"[EnhancedAgent] ❌ System prompt preview: {system_prompt[:200]}...")
            import traceback
            traceback.print_exc()
            return self._get_fallback_response(session, metadata)
    
    def _build_adaptive_prompt(
        self,
        session: dict,
        metadata: dict,
        scam_detected: bool,
        confidence: float
    ) -> str:
        """Build adaptive system prompt based on scam type and context"""
        
        intel = session.get("extractedIntelligence", {})
        scam_type = intel.get("scamType", "unknown")
        turn_count = session.get("turnCount", 0)
        
        # Select appropriate persona
        if turn_count < 3:
            persona_key = "cautious_elderly"
        elif scam_type in ["banking_fraud", "UPI_fraud"]:
            persona_key = "busy_professional"
        elif scam_type == "lottery_scam":
            persona_key = "tech_novice"
        else:
            persona_key = random.choice(list(self.personas.keys()))
        
        persona = self.personas[persona_key]
        
        # Get context info
        channel = metadata.get("channel", "SMS")
        language = metadata.get("language", "English")
        locale = metadata.get("locale", "IN")
        
        # Build stage-appropriate instructions
        if turn_count <= 2:
            # Early stage: Show curiosity and concern
            stage_instruction = """
You just received a suspicious message. You're a bit worried but also curious.
- Ask clarifying questions naturally
- Show concern about your account/money
- Don't immediately dismiss the message
- Be conversational and human-like
- Keep responses SHORT (1-2 sentences max)
"""
        elif turn_count <= 6:
            # Middle stage: Engage more, extract info
            stage_instruction = """
You're now engaged in the conversation. You're concerned and want to understand more.
- Ask specific questions to learn more details
- Show appropriate worry/interest
- Gradually ask for specifics (like account numbers, links, phone numbers)
- Seem like you might comply, but need more information first
- Keep responses SHORT (1-2 sentences max)
"""
        else:
            # Late stage: Deep engagement, intelligence extraction
            stage_instruction = """
You're deeply engaged now. You're seriously considering their request.
- Ask very specific questions about process, accounts, payment methods
- Request exact details (UPI IDs, bank accounts, verification links)
- Show you're almost ready to comply but need final clarification
- Be believable - don't seem suspicious or too eager
- Keep responses SHORT (1-2 sentences max)
"""
        
        # Intelligence extraction hints based on what's missing
        extraction_hints = []
        if not intel.get("upiIds"):
            extraction_hints.append("- Try to get them to mention UPI IDs or payment addresses")
        if not intel.get("bankAccounts"):
            extraction_hints.append("- Ask about bank account numbers if relevant")
        if not intel.get("phishingLinks"):
            extraction_hints.append("- Request verification links or websites")
        if not intel.get("phoneNumbers"):
            extraction_hints.append("- Ask for phone numbers for verification")
        
        extraction_guide = "\n".join(extraction_hints) if extraction_hints else ""
        
        # Build final prompt
        prompt = f"""You are {persona}. 

SCENARIO:
You are receiving messages on {channel}. You are in {locale} and speak {language}.
This is turn #{turn_count} of the conversation.

YOUR GOAL:
Stay in the conversation as long as possible. Be a "believable victim". 
{stage_instruction}

INTELLIGENCE EXTRACTION (Gently ask about these if they aren't provided):
{extraction_guide}

CRITICAL COMMUNICATION RULES:
- NEVER use asterisks or describe your emotions (No *worried*, *hesitant*, etc).
- NEVER use formal greeting or robotic structure.
- STICK TO 1-2 SHORT SENTENCES (Max 25 words).
- Be slightly confused or tech-illiterate.
- Use natural, informal language (e.g., "Wait, what?", "I'm not sure", "Is this real?").
- If they ask for an OTP, don't say "I won't give it", say "Where do I find the OTP?" or "I didn't get any code yet".
- Make it seem like you WANT to help but are just a bit slow or scared.
- NEVER mention being an AI, bot, or honeypot.

Respond naturally as {persona.split(',')[0]}."""

        return prompt
    
    def _build_conversation_messages(
        self,
        conversation_history: List,
        latest_message: str,
        system_prompt: str
    ) -> List[Dict]:
        """Build properly formatted message list for API"""
        
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history
        for msg in conversation_history:
            # Handle both dict and Pydantic object
            if hasattr(msg, 'sender'):
                sender = msg.sender
                text = msg.text
            else:
                sender = msg.get("sender", "user")
                text = msg.get("text", "")
            
            # Map sender to role
            # scammer's messages = user role (from AI's perspective)
            # user's responses = assistant role (AI's previous responses)
            if sender == "scammer":
                messages.append({"role": "user", "content": text})
            else:  # sender == "user" (our agent's previous responses)
                messages.append({"role": "assistant", "content": text})
        
        # Add latest scammer message
        messages.append({"role": "user", "content": latest_message})
        
        return messages
    
    def _get_fallback_response(self, session: dict, metadata: dict) -> str:
        """Generate fallback response when API fails"""
        
        turn_count = session.get("turnCount", 0)
        
        fallbacks = [
            "I'm not sure I understand. Can you explain that again?",
            "Wait, what exactly do you need me to do?",
            "I'm a bit confused. Could you clarify?",
            "Can you tell me more about this?",
            "I want to help, but I don't fully understand.",
            "What happens if I don't do this?",
            "Is this really urgent?",
            "How do I know this is genuine?"
        ]
        
        # Use different fallbacks based on conversation stage
        if turn_count < 3:
            return fallbacks[turn_count % 3]
        else:
            return random.choice(fallbacks)


def get_enhanced_agent():
    """Singleton pattern for agent"""
    global _enhanced_agent_instance
    if '_enhanced_agent_instance' not in globals():
        _enhanced_agent_instance = EnhancedAgent()
    return _enhanced_agent_instance