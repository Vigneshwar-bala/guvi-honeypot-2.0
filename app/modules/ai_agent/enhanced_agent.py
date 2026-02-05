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
            
            # Call LLM
            response = self.client.chat.completions.create(
                model="anthropic/claude-3-haiku",
                messages=messages,
                temperature=0.9,  # Increased for more variability
                max_tokens=150,
                top_p=0.9
            )
            
            result = response.choices[0].message.content.strip()
            
            # Post-processing: Remove any pesky emotion tags likely to be hallucinated
            import re
            # Remove anything between asterisks
            result = re.sub(r'\*.*?\*', '', result).strip()
            # Remove leading bullet points or common emotion labels followed by colon or space
            result = re.sub(r'^(worried|hesitant|confused|scared|suspicious|concerned)[:\s]+', '', result, flags=re.IGNORECASE).strip()
            
            print(f"[EnhancedAgent] ✅ Response generated: {len(result)} chars")
            
            if not result or len(result) < 2:
                return self._get_fallback_response(session, metadata)
            
            return result
        
        except Exception as e:
            print(f"[EnhancedAgent] ❌ Error: {str(e)}")
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
        
        # Persona selection logic...
        persona_key = "cautious_elderly" if turn_count < 3 else "busy_professional"
        persona = self.personas.get(persona_key, self.personas["cautious_elderly"])
        
        # Build stage-appropriate instructions
        if turn_count <= 2:
            stage_instruction = "Show confusion and worry. Ask basic questions."
        elif turn_count <= 7:
            stage_instruction = "Engage deeper. Seem like you might comply but are 'stuck' or need help."
        else:
            stage_instruction = "Directly ask for the details we need (UPI, links) while pretending to be ready to pay."

        extraction_hints = []
        if not intel.get("upiIds"): extraction_hints.append("- 'Wait, what's a UPI ID?' or 'Can I just send to your phone number?'")
        if not intel.get("bankAccounts"): extraction_hints.append("- 'Do I need to give you my card or just the account?'")
        
        extraction_guide = "\n".join(extraction_hints)
        
        # Build final prompt with extreme focus on format
        prompt = f"""You are {persona}. 

MANDATORY RESPONSE FORMAT:
- NO asterisks like *worried*. 
- NO descriptions of your tone.
- NO labels at the start.
- Length MUST be variable: sometimes just 3 words, sometimes 15 words.
- MAX 2 sentences. 
- Type like a human on a phone: small mistakes are okay, lowercase is okay.

YOUR GOAL:
Stay engaged. Don't be too smart. Act like you are trying to follow their instructions but are confused.

EXTRACTION GUIDE:
{extraction_guide}

Respond naturally as {persona.split(',')[0]}."""

        return prompt
    
    def _build_conversation_messages(
        self,
        conversation_history: List,
        latest_message: str,
        system_prompt: str
    ) -> List[Dict]:
        """Build properly formatted message list for API with history cleaning"""
        import re
        messages = [{"role": "system", "content": system_prompt}]
        
        for msg in conversation_history:
            if hasattr(msg, 'sender'):
                sender, text = msg.sender, msg.text
            else:
                sender, text = msg.get("sender", "user"), msg.get("text", "")
            
            # CLEAN HISTORY: Strip any existing tags from the history so the model doesn't copy them
            clean_text = re.sub(r'\*.*?\*', '', text).strip()
            
            if sender == "scammer":
                messages.append({"role": "user", "content": clean_text})
            else:
                messages.append({"role": "assistant", "content": clean_text})
        
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