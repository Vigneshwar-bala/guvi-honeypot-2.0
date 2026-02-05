import requests
import json

url = "http://127.0.0.1:8001/honeypot/message"
session_id = "test_session_audit_ready_101"
api_key = "guvi-honeypot-demo-key"

headers = {
    "x-api-key": api_key,
    "Content-Type": "application/json"
}

messages = [
    "Hello, I am from your bank. Urgent action required.",
    "Your KYC is pending. Please verify at http://scam-link.com",
    "Send 5000 to upi@vpa to avoid account block.",
    "Are you there? Send it now!"
]

for msg in messages:
    print(f"\nSending Message: {msg}")
    data = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": msg
        }
    }
    try:
        response = requests.post(url, json=data, headers=headers)
        print(f"Status Code: {response.status_code}")
        print("Response JSON:")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")
