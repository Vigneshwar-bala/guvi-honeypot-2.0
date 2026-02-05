
import sys
import os

# Mock the session
session = {
    "sessionId": "test_debug",
    "turnCount": 0,
    "conversationHistory": [],
    "extractedIntelligence": {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "amounts": [],
        "employeeIds": [],
        "seniorNames": [],
        "branchAddresses": []
    },
    "claims": {},
    "current_goal": "upiIds",
    "flags": {}
}

# Import the class
sys.path.append(os.getcwd())
from app.modules.ai_agent.enhanced_agent import EnhancedAgent

agent = EnhancedAgent()

# Test string with multiple data points
test_text = "Hello, I am Varun Sharma, senior manager at Delhi branch. Send Rs 50,000 to upi sbi.verify@bank or account 123456789012. My extension is 9876543210. ID: SBI991"

print("--- TESTING EXTRACTION ---")
agent._extract_intelligence(session, test_text)

print(f"Goal Logic Check: {agent._determine_next_goal(session)}")
print(f"Extracted: {session['extractedIntelligence']}")

# Verification matches
assert "sbi.verify@bank" in session['extractedIntelligence']['upiIds']
assert "123456789012" in session['extractedIntelligence']['bankAccounts']
assert "9876543210" in session['extractedIntelligence']['phoneNumbers']
assert "50,000" in session['extractedIntelligence']['amounts']
assert "SBI991" in session['extractedIntelligence']['employeeIds']
assert "Varun Sharma" in session['extractedIntelligence']['seniorNames']
assert "Delhi" in session['extractedIntelligence']['branchAddresses']

print("\n✅ EXTRACTION VERIFIED: All fields captured accurately!")
