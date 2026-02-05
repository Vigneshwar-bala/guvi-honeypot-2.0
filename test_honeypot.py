import requests
import json
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
API_KEY = "guvi-honeypot-demo-key"

def test_health():
    """Test health endpoint"""
    print("\n" + "="*80)
    print("TEST 1: Health Check")
    print("="*80)
    
    response = requests.get(f"{BASE_URL}/")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 200
    print("✅ Health check passed")


def test_scam_detection_basic():
    """Test basic scam detection"""
    print("\n" + "="*80)
    print("TEST 2: Basic Banking Scam Detection")
    print("="*80)
    
    payload = {
        "sessionId": f"test-session-{datetime.now().timestamp()}",
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately.",
            "timestamp": int(datetime.now().timestamp() * 1000)
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
    
    response = requests.post(
        f"{BASE_URL}/honeypot/message",
        json=payload,
        headers=headers
    )
    
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {json.dumps(result, indent=2)}")
    
    assert response.status_code == 200
    assert result["status"] == "success"
    assert len(result["reply"]) > 0
    print("✅ Basic scam detection passed")
    
    return result


def test_multi_turn_conversation():
    """Test multi-turn conversation with intelligence extraction"""
    print("\n" + "="*80)
    print("TEST 3: Multi-Turn Conversation with UPI Scam")
    print("="*80)
    
    session_id = f"test-session-multi-{datetime.now().timestamp()}"
    conversation_history = []
    
    # Turn 1
    print("\n--- Turn 1 ---")
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Congratulations! You have won Rs 50,000 lottery prize.",
            "timestamp": int(datetime.now().timestamp() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "WhatsApp",
            "language": "English",
            "locale": "IN"
        }
    }
    
    headers = {"x-api-key": API_KEY, "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/honeypot/message", json=payload, headers=headers)
    result1 = response.json()
    print(f"AI: {result1['reply']}")
    
    conversation_history.append({
        "sender": "scammer",
        "text": payload["message"]["text"],
        "timestamp": payload["message"]["timestamp"]
    })
    conversation_history.append({
        "sender": "user",
        "text": result1["reply"],
        "timestamp": int(datetime.now().timestamp() * 1000)
    })
    
    # Turn 2
    print("\n--- Turn 2 ---")
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "To claim your prize, please send Rs 500 processing fee to scammer@paytm",
            "timestamp": int(datetime.now().timestamp() * 1000)
        },
        "conversationHistory": conversation_history,
        "metadata": {
            "channel": "WhatsApp",
            "language": "English",
            "locale": "IN"
        }
    }
    
    response = requests.post(f"{BASE_URL}/honeypot/message", json=payload, headers=headers)
    result2 = response.json()
    print(f"AI: {result2['reply']}")
    
    conversation_history.append({
        "sender": "scammer",
        "text": payload["message"]["text"],
        "timestamp": payload["message"]["timestamp"]
    })
    conversation_history.append({
        "sender": "user",
        "text": result2["reply"],
        "timestamp": int(datetime.now().timestamp() * 1000)
    })
    
    # Turn 3
    print("\n--- Turn 3 ---")
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Click here to verify: http://fake-lottery-claim.com/verify",
            "timestamp": int(datetime.now().timestamp() * 1000)
        },
        "conversationHistory": conversation_history,
        "metadata": {
            "channel": "WhatsApp",
            "language": "English",
            "locale": "IN"
        }
    }
    
    response = requests.post(f"{BASE_URL}/honeypot/message", json=payload, headers=headers)
    result3 = response.json()
    print(f"AI: {result3['reply']}")
    
    print("✅ Multi-turn conversation passed")
    return result3


def test_stats():
    """Test stats endpoint"""
    print("\n" + "="*80)
    print("TEST 4: Statistics Endpoint")
    print("="*80)
    
    response = requests.get(f"{BASE_URL}/stats")
    print(f"Status: {response.status_code}")
    stats = response.json()
    print(f"Response: {json.dumps(stats, indent=2)}")
    
    assert response.status_code == 200
    print("✅ Stats endpoint passed")


def test_invalid_api_key():
    """Test invalid API key handling"""
    print("\n" + "="*80)
    print("TEST 5: Invalid API Key")
    print("="*80)
    
    payload = {
        "sessionId": "test-invalid-key",
        "message": {
            "sender": "scammer",
            "text": "Test message",
            "timestamp": int(datetime.now().timestamp() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    headers = {
        "x-api-key": "invalid-key-12345",
        "Content-Type": "application/json"
    }
    
    response = requests.post(
        f"{BASE_URL}/honeypot/message",
        json=payload,
        headers=headers
    )
    
    print(f"Status: {response.status_code}")
    assert response.status_code == 401
    print("✅ Invalid API key test passed")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("🚀 STARTING HONEYPOT API TESTS")
    print("="*80)
    
    try:
        test_health()
        test_scam_detection_basic()
        test_multi_turn_conversation()
        test_stats()
        test_invalid_api_key()
        
        print("\n" + "="*80)
        print("✅ ALL TESTS PASSED!")
        print("="*80 + "\n")
    
    except Exception as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()