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
                temperature=1.0,  # Max temperature for ultimate variety
                max_tokens=150,
                top_p=0.9
            )
            
            result = response.choices[0].message.content.strip()
            
            # Post-processing: CRITICAL CLEANING
            import re
            
            # 1. Remove anything between asterisks
            result = re.sub(r'\*.*?\*', '', result).strip()
            
            # 2. Remove repetitive AI phrases at the start
            forbidden_starts = [
                r"^i'm sorry", r"^sorry", r"^i apologize", r"^but", r"^i understand", 
                r"^as a", r"^however", r"^wait,"
            ]
            for pattern in forbidden_starts:
                result = re.sub(pattern, '', result, flags=re.IGNORECASE).strip()
            
            # 3. Final cleanup - remove leading symbols or stray punctuation from cleaning
            result = re.sub(r'^[,.\s!]+', '', result).strip()
            
            # 4. Capitalize first letter if it was lost in cleaning
            if result:
                result = result[0].upper() + result[1:]
            
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
        turn_count = session.get("turnCount", 0)
        
        # Randomize personality slightly to break patterns
        personalities = [
            "a bit scatterbrained and easily distracted",
            "very worried about their savings and keeps asking 'is my money okay?'",
            "suspicious of technology but trusts 'official' sounding people",
            "impatient and wants to get this over with because they are 'cooking dinner'"
        ]
        chosen_trait = random.choice(personalities)
        
        persona_key = "cautious_elderly" if turn_count < 3 else "busy_professional"
        persona = self.personas.get(persona_key, self.personas["cautious_elderly"])

        # Build stage-appropriate instructions (The "Best of Both" Logic)
        if turn_count <= 2:
            stage_instruction = "Reaction: Immediate worry. 'Oh no, is my money safe?'. Provide a FAKE or wrong account number if they ask, to see if they 'verify' it anyway."
        elif turn_count <= 7:
            stage_instruction = "The Struggle: Act like you are trying to give them what they want but you are 'tech-confused'. Give a fake 4-digit OTP like '5678' and ask 'is this the one?'. If it fails, ask for their UPI ID or a link to do it 'manually'."
        else:
            stage_instruction = "The Loop: Keep them on the hook. 'Wait, I typed it wrong, tell me the UPI again'. 'My screen went black, what was the link?'. Be persistent but never compliant with real data."

        extraction_hints = []
        if not intel.get("upiIds"): extraction_hints.append("- 'Wait, what is the UPI? Tell me slowly so I can type it into my app.'")
        if not intel.get("bankAccounts"): extraction_hints.append("- 'Is this for my SBI or HDFC? I have two.'")
        
        extraction_guide = "\n".join(extraction_hints)
        
        # Build final prompt
        prompt = f"""You are {persona}, and you are {chosen_trait}. 

ROLE:
You are the RECIPIENT of a scam message. Your goal is to keep them talking.
Match the scammer's tone (Formal -> Simple English, Hinglish -> Hinglish).

SCENARIO LOGIC:
{stage_instruction}

MANDATORY RULES:
- NO asterisks (*worried*). NO "I'm sorry" or "But".
- Use lowercase. Short sentences (Max 15 words).
- Mirror the scammer: If they are English, you are English. If they are Hinglish, you are Hinglish.
- If they ask for OTP/PIN: ALWAYS give a fake one first (e.g., 4432, 9981). 
- If they say it's wrong: Say 'Oh let me check again... wait my app is loading'.

EXTRACTION FOCUS:
{extraction_guide}

Respond naturally as {persona.split(',')[0]} would in a chat."""

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