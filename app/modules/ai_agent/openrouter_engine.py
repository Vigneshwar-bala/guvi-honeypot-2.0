import os
from typing import List, Dict
from openai import OpenAI

class OpenRouterEngine:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not found in environment variables")
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://openrouter.ai/api/v1",
        )
    
    def generate_response(self, conversation_history: List[Dict], latest_message: str, metadata) -> str:
        """Generate contextual response using OpenRouter API"""
        try:
            print("\n[OpenRouterEngine.generate_response] Starting...")

            system_prompt = self._build_system_prompt(metadata)
            print(f"[OpenRouterEngine.generate_response] System prompt length: {len(system_prompt)}")

            messages = self._build_messages(conversation_history, latest_message, system_prompt)
            print(f"[OpenRouterEngine.generate_response] Messages count: {len(messages)}")

            print(f"[OpenRouterEngine.generate_response] Calling OpenRouter API...")
            print(f"[OpenRouterEngine.generate_response] Model: openrouter/free")
            print(f"[OpenRouterEngine.generate_response] API Key starts with: {self.api_key[:20]}...")

            response = self.client.chat.completions.create(
                model="meta-llama/llama-3.3-70b-instruct:free",
                messages=messages,
                temperature=0.7,
                max_tokens=150
            )

            result = response.choices[0].message.content.strip()
            print(f"[OpenRouterEngine.generate_response] ✅ API call successful")
            print(f"[OpenRouterEngine.generate_response] Response length: {len(result)}")
            print(f"[OpenRouterEngine.generate_response] Response preview: {result[:100]}...")

            # Minimal retry guard for empty or zero-length responses
            if not result or len(result.strip()) == 0:
                print(f"[OpenRouterEngine.generate_response] ⚠️  Empty response, retrying once...")
                response = self.client.chat.completions.create(
                    model="openrouter/free",
                    messages=messages,
                    temperature=0.7,
                    max_tokens=150
                )
                result = response.choices[0].message.content.strip()
                print(f"[OpenRouterEngine.generate_response] Retry response length: {len(result)}")

            if not result:
                print(f"[OpenRouterEngine.generate_response] ⚠️  WARNING: Result still empty after retry!")
                return "I'm not sure I understand. Can you explain that differently?"

            return result

        except Exception as e:
            print(f"[OpenRouterEngine.generate_response] ❌ API call failed")
            print(f"[OpenRouterEngine.generate_response] Exception: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            return "I'm not sure I understand. Can you explain that differently?"
    
    def _build_system_prompt(self, metadata) -> str:
        """Build system prompt based on metadata"""
        # Convert metadata object to dict if needed
        if hasattr(metadata, '__dict__'):
            metadata_dict = metadata.__dict__
        elif isinstance(metadata, dict):
            metadata_dict = metadata
        else:
            metadata_dict = {}
        
        channel = metadata_dict.get("channel", "Unknown")
        language = metadata_dict.get("language", "English")
        locale = metadata_dict.get("locale", "IN")
        
        # Determine conversation stage based on turn count for consistent persona
        turn_count = metadata_dict.get("turn_count", 0)

        if turn_count <= 2:
            # Early stage: Show curiosity and concern
            stage_instruction = "You've just received this message and are a bit worried but curious. Ask clarifying questions naturally and show concern about your account/money."
        elif turn_count <= 6:
            # Middle stage: Engage more, extract info
            stage_instruction = "You're now engaged in the conversation and concerned. Ask specific questions to learn more details and seem like you might comply but need more information first."
        else:
            # Late stage: Deep engagement, intelligence extraction
            stage_instruction = "You're deeply engaged now and seriously considering their request. Ask very specific questions about process, accounts, payment methods, and request exact details."

        return f"""You are a common Indian user who is not very tech-savvy.
You've just received a potentially suspicious message via {channel}.
You are cautious but willing to ask questions.
{stage_instruction}
Respond in {language} in a natural, human-like way.
Keep your response short (1-2 sentences maximum).
Ask clarifying questions to understand better and sustain the conversation naturally.
Show concern but remain curious - don't immediately dismiss the message.
Be conversational, not robotic.
Your location: {locale}"""
    
    def _build_messages(self, conversation_history: List[Dict], latest_message: str, system_prompt: str) -> List[Dict]:
        """Build message list for API"""
        messages = []
        
        for msg in conversation_history:
            sender = msg.get("sender", "user")
            text = msg.get("text", "")
            
            if sender == "scammer":
                messages.append({"role": "assistant", "content": text})
            else:
                messages.append({"role": "user", "content": text})
        
        messages.append({"role": "assistant", "content": latest_message})
        
        return [{"role": "system", "content": system_prompt}] + messages

openrouter_engine = None

def get_openrouter_engine():
    global openrouter_engine
    if openrouter_engine is None:
        openrouter_engine = OpenRouterEngine()
    return openrouter_engine
