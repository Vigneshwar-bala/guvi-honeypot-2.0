import requests
import json
import time

API_URL = "http://127.0.0.1:8000/honeypot/message"
API_KEY = "guvi-honeypot-demo-key"

print("=" * 80)
print("VERIFYING AI INTEGRATION WITH OPENROUTER")
print("=" * 80)
print("\nSending the SAME message 3 times:")
print("'Your bank account will be blocked. Verify immediately.'\n")
print("If responses are DIFFERENT each time = AI is working ✅")
print("If responses are IDENTICAL each time = Still using hardcoded ❌\n")

message_text = "Your bank account will be blocked. Verify immediately."
responses = []

for i in range(3):
    payload = {
        "sessionId": f"test-session-{i}",
        "message": {
            "sender": "scammer",
            "text": message_text,
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            reply = data.get("reply", "ERROR")
            responses.append(reply)
            print(f"Response {i+1}: {reply}")
        else:
            print(f"Response {i+1}: ERROR (Status {response.status_code})")
            responses.append("ERROR")
    except Exception as e:
        print(f"Response {i+1}: ERROR ({str(e)})")
        responses.append("ERROR")
    
    if i < 2:
        time.sleep(1)

print("\n" + "=" * 80)
print("VERDICT:")
print("=" * 80)

if len(set(responses)) > 1:
    print("✅ SUCCESS: Responses are DIFFERENT!")
    print("   AI integration is working correctly.")
    print(f"   Got {len(set(responses))} unique responses out of 3 attempts.")
    print("\n   Your project is now truly AGENTIC! 🎉")
else:
    print("❌ FAILED: All responses are IDENTICAL")
    print("   This means hardcoded responses are still being used.")
    print("   Possible issues:")
    print("   1. Server not running")
    print("   2. OPENROUTER_API_KEY not set in .env")
    print("   3. OpenRouter API connection failed")

print("=" * 80)
