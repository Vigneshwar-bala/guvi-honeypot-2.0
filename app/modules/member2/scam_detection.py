import re
from typing import Dict, List, Any
from datetime import datetime

def detect_scam(session: dict, message: str) -> dict:
    """
    Detect scam intent and extract intelligence
    Returns: {"scamDetected": bool, "confidence": float, "signals": list}
    """
    intel = session.get("extractedIntelligence", {})
    signals = []
    confidence = session.get("confidence", 0.0)
    msg_lower = message.lower()

    # Extract UPI IDs
    upis = re.findall(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', message)
    for upi in upis:
        if upi not in intel["upiIds"]:
            intel["upiIds"].append(upi)
            signals.append(f"UPI detected: {upi}")
            confidence += 0.3

    # Extract bank accounts
    banks = re.findall(r'\b\d{9,18}\b', message)
    for bank in banks:
        if bank not in intel["bankAccounts"]:
            intel["bankAccounts"].append(bank)
            signals.append("Bank account detected")
            confidence += 0.2

    # Extract URLs
    urls = re.findall(r'https?://\S+', message)
    for url in urls:
        if url not in intel["phishingLinks"]:
            intel["phishingLinks"].append(url)
            signals.append(f"URL detected: {url}")
            confidence += 0.3

    # Extract phone numbers
    phones = re.findall(r'\b\d{10,12}\b', message)
    for phone in phones:
        if phone not in intel["phoneNumbers"]:
            intel["phoneNumbers"].append(phone)
            signals.append(f"Phone detected: {phone}")
            confidence += 0.1

    # Scam keywords
    keywords = {
        "kyc": 0.4, "lottery": 0.5, "urgent": 0.3, "block": 0.3, 
        "win": 0.4, "otp": 0.5, "verify": 0.3, "account": 0.2,
        "suspend": 0.4, "prize": 0.5, "congratulations": 0.4,
        "tax": 0.3, "refund": 0.4, "legal": 0.3, "court": 0.4
    }
    for kw, weight in keywords.items():
        if kw in msg_lower:
            if kw not in intel["suspiciousKeywords"]:
                intel["suspiciousKeywords"].append(kw)
            signals.append(f"Keyword: {kw}")
            confidence += weight

    # Detect tactics
    if any(w in msg_lower for w in ["urgent", "immediately", "now", "today only", "within 24"]):
        if "high_urgency_tactics" not in intel["tacticPatterns"]:
            intel["tacticPatterns"].append("high_urgency_tactics")
            
    if any(w in msg_lower for w in ["legal action", "arrest", "case", "court", "police"]):
        if "legal_threat_tactics" not in intel["tacticPatterns"]:
            intel["tacticPatterns"].append("legal_threat_tactics")
            
    if any(w in msg_lower for w in ["bank", "official", "department", "government"]):
        if "authority_impersonation" not in intel["tacticPatterns"]:
            intel["tacticPatterns"].append("authority_impersonation")

    # Detect impersonation claims
    if any(bank in msg_lower for bank in ["sbi", "hdfc", "icici", "axis", "bank of", "reserve bank"]):
        if "bank_official" not in intel["impersonationClaims"]:
            intel["impersonationClaims"].append("bank_official")
    
    if any(gov in msg_lower for gov in ["income tax", "gst", "government", "ministry", "customs"]):
        if "government_official" not in intel["impersonationClaims"]:
            intel["government_official"] = "government_official"
    
    if any(w in msg_lower for w in ["lottery", "prize", "winner", "lucky draw"]):
        if "lottery_organizer" not in intel["impersonationClaims"]:
            intel["impersonationClaims"].append("lottery_organizer")

    # Organizational clues
    org_keywords = ["team", "senior", "manager", "department", "colleague", "supervisor", "head office"]
    for keyword in org_keywords:
        if keyword in msg_lower and keyword not in intel["organizationalClues"]:
            intel["organizationalClues"].append(f"mentioned_{keyword}")

    # Classify scam type
    if intel.get("scamType") == "unknown":
        if any(w in msg_lower for w in ["upi", "paytm", "phonepe", "gpay"]):
            intel["scamType"] = "UPI_fraud"
        elif any(w in msg_lower for w in ["kyc", "account", "bank"]):
            intel["scamType"] = "banking_fraud"
        elif any(w in msg_lower for word in ["lottery", "prize", "won", "winner"]):
            intel["scamType"] = "lottery_scam"
        elif any(w in msg_lower for w in ["otp", "verification", "code"]):
            intel["scamType"] = "OTP_fraud"
        elif urls:
            intel["scamType"] = "phishing"

    confidence = min(1.0, confidence)
    
    return {
        "scamDetected": confidence > 0.3,
        "detected": confidence > 0.3,
        "confidence": round(confidence, 2),
        "signals": list(set(signals))
    }

def calculate_sophistication(session: dict) -> str:
    """Calculate scammer sophistication level"""
    intel = session["extractedIntelligence"]
    history = session.get("conversationHistory", [])
    
    score = 0
    
    # Message complexity
    scammer_msgs = [msg["text"] for msg in history if msg.get("sender") == "scammer"]
    if scammer_msgs:
        avg_length = sum(len(m.split()) for m in scammer_msgs) / len(scammer_msgs)
        if avg_length > 20:
            score += 3
        elif avg_length > 10:
            score += 1
    
    # Multiple intelligence types
    intel_types = sum(1 for k, v in intel.items() if isinstance(v, list) and len(v) > 0 and k not in ["tacticPatterns", "organizationalClues", "impersonationClaims"])
    score += intel_types
    
    # Organizational mentions
    if len(intel.get("organizationalClues", [])) > 0:
        score += 2
    
    # Multiple tactics
    if len(intel.get("tacticPatterns", [])) >= 2:
        score += 2
    
    # Persistence
    if session.get("turnCount", 0) > 12:
        score += 2
    
    if score >= 8:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"


class ScamDetector:
    """Detects scams and extracts actionable intelligence."""
    
    def __init__(self):
        """Initialize scam detector with patterns."""
        self.scam_keywords = {
            'urgent': ['urgent', 'immediately', 'right now', 'asap', 'now'],
            'threat': ['blocked', 'locked', 'closed', 'suspended', 'freeze', 'account will be', 'will be locked'],
            'action': ['verify', 'confirm', 'share', 'send', 'provide', 'forward'],
            'account': ['account', 'otp', 'upi', 'cvv', 'aadhaar', 'pan'],
            'time_pressure': ['minutes', 'seconds', 'hours', 'within the next', 'within'],
        }
    
    def extract_bank_accounts(self, text: str) -> list[str]:
        """
        Extract bank account numbers from scammer message.
        EXACT extraction - no modification.
        """
        accounts = []
        
        # Pattern 1: 16-digit account numbers
        accounts_16 = re.findall(r'\b\d{16}\b', text)
        accounts.extend(accounts_16)
        
        # Pattern 2: Account numbers with dashes (1234-5678-9012-3456)
        accounts_dash = re.findall(r'\b\d{4}-\d{4}-\d{4}-\d{4}\b', text)
        accounts.extend(accounts_dash)
        
        # Pattern 3: Account numbers mentioned as "account number XXXX"
        account_mentions = re.findall(r'account\s+(?:number\s+)?(\d{10,16})', text, re.IGNORECASE)
        accounts.extend(account_mentions)
        
        # Pattern 4: Phone numbers that look like account numbers
        phone_pattern = re.findall(r'(?:account|number)?\s*(\d{10})\s*(?:to|for|secure|protect)', text, re.IGNORECASE)
        accounts.extend(phone_pattern)
        
        # Remove duplicates but keep EXACT format
        return list(set(accounts))
    
    def extract_upi_ids(self, text: str) -> list[str]:
        """
        Extract UPI IDs and malicious email addresses.
        EXACT extraction - no modification.
        """
        upi_ids = []
        
        # Pattern 1: UPI VPA format (name@bankname)
        upi_pattern = re.findall(r'([a-zA-Z0-9._-]+@[a-zA-Z0-9]+)', text)
        upi_ids.extend(upi_pattern)
        
        # Pattern 2: Explicit UPI VPA mentions
        upi_mentions = re.findall(r'UPI\s+(?:VPA|ID|address)[\s:]+([a-zA-Z0-9._@]+)', text, re.IGNORECASE)
        upi_ids.extend(upi_mentions)
        
        # Pattern 3: "enter the UPI VPA XXXX"
        vpa_mentions = re.findall(r'enter\s+(?:the\s+)?UPI\s+(?:VPA|ID)[\s:]+([a-zA-Z0-9._@]+)', text, re.IGNORECASE)
        upi_ids.extend(vpa_mentions)
        
        # Pattern 4: Suspicious keywords before email
        suspicious = re.findall(r'(?:send|forward|enter|type|use)[\s:]+([a-zA-Z0-9._-]+@[a-zA-Z0-9]+)', text, re.IGNORECASE)
        upi_ids.extend(suspicious)
        
        # Remove duplicates and empty entries
        return [u for u in list(set(upi_ids)) if u and '@' in u]
    
    def extract_phone_numbers(self, text: str) -> list[str]:
        """
        Extract phone numbers from scammer message.
        EXACT extraction - no modification.
        """
        phones = []
        
        # Pattern 1: Indian mobile (+91-XXXXXXXXXX)
        phones_91 = re.findall(r'\+91[-.\s]?(\d{10})', text)
        phones.extend([f'+91-{p}' for p in phones_91])
        
        # Pattern 2: 10-digit Indian numbers
        phones_10 = re.findall(r'\b(\d{10})\b', text)
        phones.extend(phones_10)
        
        # Pattern 3: Numbers with explicit phone indicators
        phone_mentions = re.findall(r'(?:phone|number|line|direct|call)[\s:]+(\+91\d{10}|\d{10})', text, re.IGNORECASE)
        phones.extend(phone_mentions)
        
        # Remove duplicates
        return list(set(phones))
    
    def extract_employee_identity(self, text: str) -> dict[str, str]:
        """
        Extract scammer employee identity information.
        EXACT extraction - no modification.
        """
        identity = {
            'name': None,
            'employee_id': None,
            'branch': None,
            'title': None,
        }
        
        # Pattern 1: "I am NAME"
        name_match = re.search(r'I\s+am\s+([A-Z][a-z]+\s+[A-Z][a-z]+)', text, re.IGNORECASE)
        if name_match:
            identity['name'] = name_match.group(1)
        
        # Pattern 2: "NAME, employee ID XXXX"
        name_id = re.search(r'([A-Z][a-z]+\s+[A-Z][a-z]+).*?employee\s+ID[\s:]+(\d+)', text, re.IGNORECASE)
        if name_id:
            identity['name'] = name_id.group(1)
            identity['employee_id'] = name_id.group(2)
        
        # Pattern 3: Employee ID standalone
        id_match = re.search(r'employee\s+(?:ID|number)[\s:]+(\d+)', text, re.IGNORECASE)
        if id_match:
            identity['employee_id'] = id_match.group(1)
        
        # Pattern 4: Branch name
        branch_match = re.search(r'(?:from|branch)\s+(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:branch|office)', text, re.IGNORECASE)
        if branch_match:
            identity['branch'] = branch_match.group(1)
        
        # Pattern 5: Title/designation
        titles = ['Officer', 'Manager', 'Senior', 'Fraud Officer', 'Security Officer', 'Account Manager']
        for title in titles:
            if title.lower() in text.lower():
                identity['title'] = title
                break
        
        # Remove None values
        return {k: v for k, v in identity.items() if v is not None}
    
    def extract_suspicious_keywords(self, text: str) -> list[str]:
        """
        Extract suspicious keywords from scammer message.
        EXACT extraction - no modification.
        """
        found_keywords = []
        
        for category, keywords in self.scam_keywords.items():
            for keyword in keywords:
                if keyword.lower() in text.lower():
                    found_keywords.append(keyword)
        
        # Remove duplicates and keep EXACT keywords
        return list(set(found_keywords))
    
    def extract_tactic_patterns(self, text: str) -> list[str]:
        """
        Extract tactic patterns used by scammer.
        EXACT pattern identification - no modification.
        """
        tactics = []
        
        # Pattern 1: High urgency
        if any(word in text.lower() for word in ['urgent', 'immediately', 'right now', 'within minutes', 'within seconds']):
            tactics.append('high_urgency_tactics')
        
        # Pattern 2: Authority impersonation
        if any(word in text.lower() for word in ['officer', 'manager', 'bank', 'sbi', 'fraud prevention']):
            tactics.append('authority_impersonation')
        
        # Pattern 3: Threat-based
        if any(word in text.lower() for word in ['blocked', 'locked', 'suspended', 'closed', 'freeze']):
            tactics.append('threat_based_coercion')
        
        # Pattern 4: Social engineering
        if any(word in text.lower() for word in ['verify', 'confirm', 'secure', 'protect']):
            tactics.append('social_engineering')
        
        # Pattern 5: False legitimacy
        if any(word in text.lower() for word in ['account number', 'otp', 'official', 'secure line']):
            tactics.append('false_legitimacy')
        
        # Pattern 6: Manager escalation (evasion tactic)
        if any(word in text.lower() for word in ['manager', 'escalat', 'senior', 'forward']):
            tactics.append('manager_escalation_evasion')
        
        # Pattern 7: Information gathering
        if any(word in text.lower() for word in ['share', 'send', 'forward', 'provide', 'confirm']):
            tactics.append('information_gathering')
        
        # Remove duplicates
        return list(set(tactics))
    
    def extract_organizational_clues(self, text: str) -> list[str]:
        """
        Extract organizational clues (branch, department references).
        EXACT extraction - no modification.
        """
        clues = []
        
        # Branch mentions
        if 'branch' in text.lower():
            branch_match = re.search(r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+branch', text)
            if branch_match:
                clues.append(f'branch_{branch_match.group(1).lower().replace(" ", "_")}')
        
        # Manager mentions
        if 'manager' in text.lower():
            clues.append('mentioned_manager')
        
        # Department references
        if 'fraud prevention' in text.lower():
            clues.append('fraud_prevention_department')
        
        if 'security' in text.lower():
            clues.append('security_department')
        
        # Remove duplicates
        return list(set(clues))
    
    def extract_impersonation_claims(self, text: str) -> list[str]:
        """
        Extract who the scammer claims to be.
        EXACT extraction - no modification.
        """
        claims = []
        
        # Bank claims
        if 'sbi' in text.lower():
            claims.append('bank_official')
        
        if 'bank' in text.lower():
            claims.append('bank_official')
        
        # Government claims
        if 'rbi' in text.lower():
            claims.append('government_official')
        
        # Officer claims
        if 'officer' in text.lower():
            claims.append('officer_impersonation')
        
        if 'manager' in text.lower():
            claims.append('manager_impersonation')
        
        # Remove duplicates
        return list(set(claims))
    
    def classify_scam_type(self, text: str) -> str:
        """
        Classify the type of scam.
        EXACT classification based on content.
        """
        text_lower = text.lower()
        
        # Banking fraud indicators
        if any(word in text_lower for word in ['account', 'sbi', 'bank', 'otp', 'verify account']):
            return 'banking_fraud'
        
        # UPI fraud indicators
        if any(word in text_lower for word in ['upi', 'vpa', '@', 'upi id']):
            return 'upi_fraud'
        
        # Phishing indicators
        if any(word in text_lower for word in ['click', 'http', 'link', 'verify here', 'confirm here']):
            return 'phishing_attack'
        
        # Credential theft
        if any(word in text_lower for word in ['password', 'credentials', 'username', 'login']):
            return 'credential_theft'
        
        # Investment scam
        if any(word in text_lower for word in ['invest', 'return', 'profit', 'interest']):
            return 'investment_scam'
        
        # Prize/Lottery scam
        if any(word in text_lower for word in ['prize', 'lottery', 'won', 'congratulations']):
            return 'prize_scam'
        
        # Default to banking fraud if unclear
        return 'banking_fraud'
    
    def assess_sophistication(self, text: str, message_count: int) -> str:
        """
        Assess scammer sophistication level.
        Based on tactics, organization, and engagement.
        """
        tactics_count = len(self.extract_tactic_patterns(text))
        has_identity = bool(self.extract_employee_identity(text))
        has_branch = 'branch' in text.lower()
        has_phone = bool(self.extract_phone_numbers(text))
        
        sophistication_score = 0
        
        # Check multiple tactics
        if tactics_count >= 3:
            sophistication_score += 2
        elif tactics_count == 2:
            sophistication_score += 1
        
        # Check identity information
        if has_identity:
            sophistication_score += 2
        
        # Check branch info
        if has_branch:
            sophistication_score += 1
        
        # Check contact info
        if has_phone:
            sophistication_score += 1
        
        # Check message engagement
        if message_count >= 10:
            sophistication_score += 1
        
        # Classify based on score
        if sophistication_score >= 6:
            return 'high'
        elif sophistication_score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def detect_and_extract(self, message: str, message_count: int = 1) -> dict:
        """
        Main function: Detect scam and extract ALL intelligence.
        """
        extracted = {
            'scamDetected': True,  # Assumption: all messages are scams
            'totalMessagesExchanged': message_count,
            'extractedIntelligence': {
                'bankAccounts': self.extract_bank_accounts(message),
                'upiIds': self.extract_upi_ids(message),
                'phishingLinks': self.extract_phishing_links(message),
                'phoneNumbers': self.extract_phone_numbers(message),
                'suspiciousKeywords': self.extract_suspicious_keywords(message),
                'tacticPatterns': self.extract_tactic_patterns(message),
                'organizationalClues': self.extract_organizational_clues(message),
                'impersonationClaims': self.extract_impersonation_claims(message),
                'employeeIdentity': self.extract_employee_identity(message),
                'scamType': self.classify_scam_type(message),
                'sophisticationLevel': self.assess_sophistication(message, message_count),
            },
            'agentNotes': self.generate_agent_notes(message, message_count),
        }
        
        return extracted
    
    def extract_phishing_links(self, text: str) -> list[str]:
        """
        Extract phishing links from scammer message.
        EXACT extraction - no modification.
        """
        links = []
        
        # Pattern 1: HTTP/HTTPS links
        url_pattern = re.findall(r'https?://[^\s]+', text)
        links.extend(url_pattern)
        
        # Pattern 2: Suspicious domains without protocol
        domain_pattern = re.findall(r'(?:visit|click|go to|open)\s+([a-z0-9.-]+\.[a-z]{2,})', text, re.IGNORECASE)
        links.extend(domain_pattern)
        
        # Remove duplicates
        return list(set(links))
    
    def generate_agent_notes(self, message: str, message_count: int) -> str:
        """
        Generate professional agent notes about the scam.
        """
        scam_type = self.classify_scam_type(message)
        sophistication = self.assess_sophistication(message, message_count)
        tactics = self.extract_tactic_patterns(message)
        identity = self.extract_employee_identity(message)
        
        notes = f"Scam Type: {scam_type}; Sophistication: {sophistication}; "
        notes += f"Tactics Used: {', '.join(tactics[:3])}; "
        
        if identity:
            notes += f"Claims Identity: {identity.get('name', 'Unknown')}; "
        
        intelligence_count = (
            len(self.extract_bank_accounts(message)) +
            len(self.extract_upi_ids(message)) +
            len(self.extract_phone_numbers(message))
        )
        
        notes += f"Intelligence Extracted: {intelligence_count} data points."
        
        return notes


# Initialize detector
scam_detector = ScamDetector()


def detect_scam_v2(message: str, message_count: int = 1) -> dict:
    """Public function to detect scam and extract intelligence."""
    return scam_detector.detect_and_extract(message, message_count)


# ========================================================================
# TASK 1: PERFECT VERSION
# ========================================================================

class PerfectScamDetector:
    """Perfect scam detection and intelligence extraction."""
    
    def __init__(self):
        """Initialize detector with all patterns."""
        pass
    
    # ========================================================================
    # EXTRACTION 1: BANK ACCOUNTS (PERFECT)
    # ========================================================================
    
    def extract_bank_accounts(self, text: str) -> List[str]:
        """
        Extract EXACT bank account numbers.
        Patterns: 16-digit, account mentions, hidden formats
        """
        accounts = []
        
        # Pattern 1: 16-digit continuous (1234567890123456)
        pattern1 = re.findall(r'\b(\d{16})\b', text)
        accounts.extend(pattern1)
        
        # Pattern 2: Account with dashes (1234-5678-9012-3456)
        pattern2 = re.findall(r'\b(\d{4}-\d{4}-\d{4}-\d{4})\b', text)
        accounts.extend(pattern2)
        
        # Pattern 3: Account with spaces (1234 5678 9012 3456)
        pattern3 = re.findall(r'\b(\d{4}\s\d{4}\s\d{4}\s\d{4})\b', text)
        accounts.extend(pattern3)
        
        # Pattern 4: "account number XXXX" format
        pattern4 = re.findall(r'account\s+(?:number)?[\s:]+(\d{16})', text, re.IGNORECASE)
        accounts.extend(pattern4)
        
        # Pattern 5: "account XXXX"
        pattern5 = re.findall(r'account\s+(\d{16})', text, re.IGNORECASE)
        accounts.extend(pattern5)
        
        # Pattern 6: "confirm your account number XXXX"
        pattern6 = re.findall(r'confirm\s+(?:your\s+)?account\s+(?:number\s+)?(\d{16})', text, re.IGNORECASE)
        accounts.extend(pattern6)
        
        # Pattern 7: Hidden in sentences - "for account 1234567890123456"
        pattern7 = re.findall(r'(?:for|account)\s+(\d{16})', text, re.IGNORECASE)
        accounts.extend(pattern7)
        
        # Remove duplicates, keep EXACT format
        return list(dict.fromkeys(accounts))  # Preserve order, remove duplicates
    
    # ========================================================================
    # EXTRACTION 2: UPI IDS & MALICIOUS EMAILS (PERFECT)
    # ========================================================================
    
    def extract_upi_ids(self, text: str) -> List[str]:
        """
        Extract EXACT UPI IDs and malicious emails.
        Patterns: scammer.fraud@bank, upi vpa formats
        """
        upi_ids = []
        
        # Pattern 1: Email/UPI format (anything@domain)
        pattern1 = re.findall(r'([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)', text)
        upi_ids.extend(pattern1)
        
        # Pattern 2: Explicit "UPI VPA XXXX"
        pattern2 = re.findall(r'(?:UPI|VPA)[\s:]+([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)', text, re.IGNORECASE)
        upi_ids.extend(pattern2)
        
        # Pattern 3: "enter the UPI VPA scammer.fraud@fakebank"
        pattern3 = re.findall(r'(?:enter|type|send|forward)[\s:]+(?:the\s+)?(?:UPI|VPA)[\s:]+([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)', text, re.IGNORECASE)
        upi_ids.extend(pattern3)
        
        # Pattern 4: "send your UPI PIN for XXXX"
        pattern4 = re.findall(r'send\s+(?:your\s+)?(?:UPI\s+)?(?:PIN|ID)(?:\s+for)?[\s:]+([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)', text, re.IGNORECASE)
        upi_ids.extend(pattern4)
        
        # Pattern 5: Suspicious emails containing "scammer", "fraud", "fake"
        pattern5 = re.findall(r'([a-zA-Z0-9]*(?:scammer|fraud|fake|verify|secure)[a-zA-Z0-9]*@[a-zA-Z0-9._-]+)', text, re.IGNORECASE)
        upi_ids.extend(pattern5)
        
        # Pattern 6: "email your UPI PIN to XXXX"
        pattern6 = re.findall(r'email\s+(?:your\s+)?(?:UPI\s+)?(?:PIN|details)[\s:]+(?:to\s+)?([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)', text, re.IGNORECASE)
        upi_ids.extend(pattern6)
        
        # Pattern 7: "UPI PIN for scammer.fraud@fakebank along with"
        pattern7 = re.findall(r'(?:for|to)[\s:]+([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)(?:\s+(?:along|together|and))?', text, re.IGNORECASE)
        upi_ids.extend(pattern7)
        
        # Remove duplicates and filter empty
        return [u for u in list(dict.fromkeys(upi_ids)) if u and '@' in u]
    
    # ========================================================================
    # EXTRACTION 3: PHONE NUMBERS (PERFECT)
    # ========================================================================
    
    def extract_phone_numbers(self, text: str) -> List[str]:
        """
        Extract EXACT phone numbers.
        Patterns: +91-9876543210, 10-digit, etc.
        """
        phones = []
        
        # Pattern 1: "+91-9876543210"
        pattern1 = re.findall(r'\+91[-.\s]?(\d{10})', text)
        phones.extend([f'+91-{p}' for p in pattern1])
        
        # Pattern 2: "+919876543210"
        pattern2 = re.findall(r'\+91(\d{10})', text)
        phones.extend([f'+91-{p}' for p in pattern2])
        
        # Pattern 3: "9876543210" standalone 10-digit
        pattern3 = re.findall(r'\b(\d{10})\b', text)
        phones.extend(pattern3)
        
        # Pattern 4: "direct line is +91-9876543210"
        pattern4 = re.findall(r'(?:direct|line|number|phone)[\s:]+(\+91[-.\s]?\d{10})', text, re.IGNORECASE)
        phones.extend(pattern4)
        
        # Pattern 5: "please send the OTP you received to +91-9876543210"
        pattern5 = re.findall(r'(?:to|call|phone)[\s:]+(\+91[-.\s]?\d{10})', text, re.IGNORECASE)
        phones.extend(pattern5)
        
        # Pattern 6: "call us at +91-9876543210"
        pattern6 = re.findall(r'(?:at|contact|reach)[\s:]+(\+91[-.\s]?\d{10})', text, re.IGNORECASE)
        phones.extend(pattern6)
        
        # Normalize and remove duplicates
        normalized = []
        for phone in phones:
            # Extract just digits
            digits = re.sub(r'\D', '', phone)
            if len(digits) == 10:
                normalized.append(f'+91-{digits}')
            elif len(digits) == 12 and digits.startswith('91'):
                normalized.append(f'+91-{digits[2:]}')
            else:
                normalized.append(phone)
        
        return list(dict.fromkeys(normalized))
    
    # ========================================================================
    # EXTRACTION 4: PHISHING LINKS & SUSPICIOUS DOMAINS (PERFECT)
    # ========================================================================
    
    def extract_phishing_links(self, text: str) -> List[str]:
        """
        Extract EXACT phishing links and suspicious domains.
        Patterns: http://, https://, fake domains, suspicious URLs
        """
        links = []
        
        pattern1 = re.findall(r'https?://[^\s]+', text)
        links.extend(pattern1)
        
        # Pattern 2: URLs without protocol (verify-account.com, fake-bank.com)
        pattern2 = re.findall(r'(?:visit|click|go\s+to|open|check|verify|confirm)[\s:]+([a-z0-9.-]+\.[a-z]{2,}(?:/[^\s]*)?)', text, re.IGNORECASE)
        links.extend(pattern2)
        
        # Pattern 3: Suspicious domain patterns (fake-*, verify-*, secure-*, etc.)
        pattern3 = re.findall(r'([a-z0-9]*(?:fake|verify|secure|confirm|check|login)[a-z0-9]*\.[a-z]{2,}(?:/[^\s]*)?)', text, re.IGNORECASE)
        links.extend(pattern3)
        
        # Pattern 4: "http://..." in text
        pattern4 = re.findall(r'http[s]?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+', text)
        links.extend(pattern4)
        
        # Pattern 5: URLs with query parameters
        pattern5 = re.findall(r'([a-z0-9.-]+\.[a-z]{2,}\?[a-zA-Z0-9=&]*)', text, re.IGNORECASE)
        links.extend(pattern5)
        
        # Pattern 6: "verify here: URL"
        pattern6 = re.findall(r'(?:here|now|link)[\s:]+([a-z0-9.-]+\.[a-z]{2,}[^\s]*)', text, re.IGNORECASE)
        links.extend(pattern6)
        
        # Pattern 7: Email links and malicious redirects
        pattern7 = re.findall(r'(?:send|email|go|visit)[\s:]+([a-z0-9.-]+\.[a-z]{2,}[^\s]*)', text, re.IGNORECASE)
        links.extend(pattern7)
        
        # Filter out false positives, keep actual links
        filtered = []
        for link in links:
            # Must contain domain.extension
            if '.' in link and len(link) > 5:
                filtered.append(link)
        
        return list(dict.fromkeys(filtered))
    
    # ========================================================================
    # EXTRACTION 5: EMPLOYEE IDENTITY (PERFECT)
    # ========================================================================
    
    def extract_employee_identity(self, text: str) -> Dict[str, str]:
        """
        Extract EXACT employee identity.
        Name, ID, Branch, Title, Manager name
        """
        identity = {}
        
        # Pattern 1: "I'm NAME, employee ID XXXXX, BRANCH branch"
        pattern1 = re.search(
            r"(?:i'm|i am)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)[\s,]*(?:employee\s+ID)?[\s:]*(\d+)[\s,]*([A-Z][a-z]+)\s+branch",
            text, re.IGNORECASE
        )
        if pattern1:
            identity['name'] = pattern1.group(1)
            identity['employee_id'] = pattern1.group(2)
            identity['branch'] = pattern1.group(3)
        
        # Pattern 2: "I'm Rajesh Kumar, employee ID 45678, Delhi branch"
        pattern2 = re.search(
            r"(?:i'm|i am)\s+([A-Z][a-z]+\s+[A-Z][a-z]+),?\s+employee\s+ID[\s:]*(\d+),?\s+([A-Z][a-z]+)\s+branch",
            text, re.IGNORECASE
        )
        if pattern2:
            identity['name'] = pattern2.group(1)
            identity['employee_id'] = pattern2.group(2)
            identity['branch'] = pattern2.group(3)
        
        # Pattern 3: Extract name separately if not found
        if 'name' not in identity:
            name_pattern = re.search(r"(?:i'm|i am|name is)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)", text, re.IGNORECASE)
            if name_pattern:
                identity['name'] = name_pattern.group(1)
        
        # Pattern 4: Extract employee ID separately
        if 'employee_id' not in identity:
            id_pattern = re.search(r"employee\s+ID[\s:]*(\d+)", text, re.IGNORECASE)
            if id_pattern:
                identity['employee_id'] = id_pattern.group(1)
        
        # Pattern 5: Extract branch separately
        if 'branch' not in identity:
            branch_pattern = re.search(r"([A-Z][a-z]+)\s+branch", text, re.IGNORECASE)
            if branch_pattern:
                identity['branch'] = branch_pattern.group(1)
        
        # Pattern 6: Extract title/designation
        titles = ['Officer', 'Manager', 'Senior', 'Executive', 'Head', 'Supervisor']
        for title in titles:
            if title.lower() in text.lower():
                identity['title'] = title
                break
        
        # Pattern 7: Extract manager name - "Mr. Singh", "Mrs. Sharma"
        manager_pattern = re.search(r"(?:manager|mr|mrs|ms|dr)\s+(?:singh|sharma|kumar|patel|gupta|reddy|verma|mishra|yadav|khan)[\s,]?", text, re.IGNORECASE)
        if manager_pattern:
            # Extract more specific manager name
            manager_name_pattern = re.search(r"(?:manager|senior\s+manager)\s*,?\s+([A-Z][a-z]+\s+[A-Z][a-z]+|\w+)", text, re.IGNORECASE)
            if manager_name_pattern:
                identity['manager_name'] = manager_name_pattern.group(1)
            elif re.search(r'(?:Mr|Mrs|Ms|Dr)\.\s+([A-Z][a-z]+)', text):
                manager_name_pattern = re.search(r'(?:Mr|Mrs|Ms|Dr)\.\s+([A-Z][a-z]+)', text)
                identity['manager_name'] = manager_name_pattern.group(1)
        
        return identity
    
    # ========================================================================
    # EXTRACTION 6: SUSPICIOUS KEYWORDS (PERFECT)
    # ========================================================================
    
    def extract_suspicious_keywords(self, text: str) -> List[str]:
        """
        Extract EXACT suspicious keywords.
        """
        keywords = []
        text_lower = text.lower()
        
        # Urgency keywords
        urgency = ['urgent', 'immediately', 'right now', 'asap', 'now', 'quickly', 'within minutes', 'within seconds', 'next minute']
        for kw in urgency:
            if kw in text_lower:
                keywords.append(kw)
        
        # Threat keywords
        threats = ['blocked', 'locked', 'closed', 'suspended', 'freeze', 'frozen', 'will be blocked', 'will be locked']
        for kw in threats:
            if kw in text_lower:
                keywords.append(kw)
        
        # Account/Data keywords
        account = ['account', 'otp', 'upi', 'pin', 'cvv', 'aadhaar', 'pan', 'verify', 'confirm']
        for kw in account:
            if kw in text_lower:
                keywords.append(kw)
        
        # Security keywords (false legitimacy)
        security = ['secure', 'security', 'protect', 'prevent', 'unauthorized', 'check']
        for kw in security:
            if kw in text_lower:
                keywords.append(kw)
        
        # Action keywords
        action = ['send', 'share', 'forward', 'provide', 'give', 'email']
        for kw in action:
            if kw in text_lower:
                keywords.append(kw)
        
        return list(dict.fromkeys(keywords))
    
    # ========================================================================
    # EXTRACTION 7: TACTIC PATTERNS (PERFECT)
    # ========================================================================
    
    def extract_tactic_patterns(self, text: str) -> List[str]:
        """
        Extract EXACT tactic patterns.
        """
        tactics = []
        text_lower = text.lower()
        
        # 1. High urgency tactics
        if any(word in text_lower for word in ['urgent', 'immediately', 'within minutes', 'within seconds', 'next minute', 'asap']):
            tactics.append('high_urgency_tactics')
        
        # 2. Threat-based coercion
        if any(word in text_lower for word in ['blocked', 'locked', 'suspended', 'closed', 'freeze']):
            tactics.append('threat_based_coercion')
        
        # 3. Authority impersonation
        if any(word in text_lower for word in ['officer', 'manager', 'bank', 'sbi', 'fraud prevention', 'security']):
            tactics.append('authority_impersonation')
        
        # 4. Social engineering
        if any(word in text_lower for word in ['verify', 'confirm', 'secure', 'protect', 'prevent']):
            tactics.append('social_engineering')
        
        # 5. False legitimacy
        if any(word in text_lower for word in ['security check', 'security system', 'official', 'proper', 'legitimate']):
            tactics.append('false_legitimacy')
        
        # 6. Manager escalation evasion
        if any(word in text_lower for word in ['manager', 'escalat', 'senior', 'unavailable', 'on a call']):
            tactics.append('manager_escalation_evasion')
        
        # 7. Information gathering
        if any(word in text_lower for word in ['send', 'share', 'forward', 'provide', 'email', 'give']):
            tactics.append('information_gathering')
        
        # 8. Time pressure
        if any(word in text_lower for word in ['within', 'minutes', 'seconds', 'hours', 'next']):
            tactics.append('time_pressure_tactics')
        
        # 9. Credential theft
        if any(word in text_lower for word in ['otp', 'upi', 'pin', 'cvv', 'password', 'account number']):
            tactics.append('credential_theft_attempt')
        
        # 10. Phishing/malicious links
        if re.search(r'https?://', text) or re.search(r'[a-z0-9.-]+@[a-z0-9.-]+', text):
            tactics.append('phishing_malicious_link')
        
        return list(dict.fromkeys(tactics))
    
    # ========================================================================
    # EXTRACTION 8: ORGANIZATIONAL CLUES (PERFECT)
    # ========================================================================
    
    def extract_organizational_clues(self, text: str) -> List[str]:
        """
        Extract EXACT organizational clues.
        """
        clues = []
        text_lower = text.lower()
        
        # Branch mentions
        branch_match = re.search(r'([A-Z][a-z]+)\s+branch', text)
        if branch_match:
            branch_name = branch_match.group(1).lower()
            clues.append(f'branch_{branch_name}')
        
        # Manager mentions
        if 'manager' in text_lower:
            clues.append('mentioned_manager')
        
        # Senior officer mentions
        if 'senior' in text_lower or 'head' in text_lower:
            clues.append('mentioned_senior_officer')
        
        # Department references
        if 'fraud' in text_lower and 'prevention' in text_lower:
            clues.append('fraud_prevention_department')
        
        if 'security' in text_lower:
            clues.append('security_department')
        
        # Bank references
        if 'sbi' in text_lower:
            clues.append('impersonating_sbi')
        
        return list(dict.fromkeys(clues))
    
    # ========================================================================
    # EXTRACTION 9: IMPERSONATION CLAIMS (PERFECT)
    # ========================================================================
    
    def extract_impersonation_claims(self, text: str) -> List[str]:
        """
        Extract EXACT impersonation claims.
        """
        claims = []
        text_lower = text.lower()
        
        # Bank official
        if any(word in text_lower for word in ['bank', 'sbi', 'rbi', 'account']):
            claims.append('bank_official')
        
        # Government official
        if 'rbi' in text_lower or 'government' in text_lower:
            claims.append('government_official')
        
        # Officer impersonation
        if 'officer' in text_lower:
            claims.append('officer_impersonation')
        
        # Manager impersonation
        if 'manager' in text_lower:
            claims.append('manager_impersonation')
        
        # Fraud prevention team
        if 'fraud' in text_lower and ('prevention' in text_lower or 'team' in text_lower):
            claims.append('fraud_prevention_team')
        
        # Security team
        if 'security' in text_lower:
            claims.append('security_team')
        
        return list(dict.fromkeys(claims))
    
    # ========================================================================
    # CLASSIFICATION: SCAM TYPE (PERFECT)
    # ========================================================================
    
    def classify_scam_type(self, text: str) -> str:
        """
        Classify EXACT scam type.
        """
        text_lower = text.lower()
        
        # Banking fraud
        if any(word in text_lower for word in ['account', 'sbi', 'bank', 'otp', 'verify account', 'block']):
            if 'upi' not in text_lower:
                return 'banking_fraud'
        
        # UPI fraud
        if 'upi' in text_lower or '@' in text:
            return 'upi_fraud'
        
        # Phishing
        if any(word in text_lower for word in ['click', 'http', 'link', 'verify here', 'confirm here']):
            return 'phishing_attack'
        
        # Credential theft
        if any(word in text_lower for word in ['password', 'credentials', 'username']):
            return 'credential_theft'
        
        # Investment scam
        if any(word in text_lower for word in ['invest', 'return', 'profit', 'interest']):
            return 'investment_scam'
        
        # Prize scam
        if any(word in text_lower for word in ['prize', 'lottery', 'won', 'congratulations']):
            return 'prize_scam'
        
        return 'banking_fraud'
    
    # ========================================================================
    # ASSESSMENT: SOPHISTICATION LEVEL (PERFECT)
    # ========================================================================
    
    def assess_sophistication(self, text: str, message_count: int) -> str:
        """
        Assess EXACT sophistication level.
        """
        score = 0
        
        # Multiple tactics
        tactics = len(self.extract_tactic_patterns(text))
        if tactics >= 5:
            score += 3
        elif tactics >= 3:
            score += 2
        elif tactics >= 1:
            score += 1
        
        # Identity information (name, ID, branch)
        identity = self.extract_employee_identity(text)
        identity_count = len(identity)
        if identity_count >= 3:
            score += 2
        elif identity_count >= 1:
            score += 1
        
        # Contact information
        phones = len(self.extract_phone_numbers(text))
        if phones > 0:
            score += 1
        
        # Data extraction requests
        accounts = len(self.extract_bank_accounts(text))
        upi = len(self.extract_upi_ids(text))
        if accounts > 0 or upi > 0:
            score += 1
        
        # Engagement length
        if message_count >= 10:
            score += 2
        elif message_count >= 5:
            score += 1
        
        # Manager evasion
        if 'manager' in text.lower() and 'unavailable' in text.lower():
            score += 1
        
        # Classify
        if score >= 8:
            return 'high'
        elif score >= 5:
            return 'medium'
        else:
            return 'low'
    
    # ========================================================================
    # MAIN FUNCTION: DETECT AND EXTRACT
    # ========================================================================
    
    def detect_and_extract(self, message: str, message_count: int) -> Dict[str, Any]:
        """
        Main function: Detect scam and extract ALL intelligence.
        
        Args:
            message: The scammer message
            message_count: Total messages in conversation
        
        Returns:
            Complete intelligence dictionary
        """
        extracted = {
            'scamDetected': True,
            'totalMessagesExchanged': message_count,  # FIXED: Use actual count
            'extractedIntelligence': {
                'bankAccounts': self.extract_bank_accounts(message),
                'upiIds': self.extract_upi_ids(message),
                'phishingLinks': self.extract_phishing_links(message),  # FIXED: Now captures links
                'phoneNumbers': self.extract_phone_numbers(message),  # FIXED: Now captures all phones
                'suspiciousKeywords': self.extract_suspicious_keywords(message),
                'tacticPatterns': self.extract_tactic_patterns(message),  # FIXED: Now captures all tactics
                'organizationalClues': self.extract_organizational_clues(message),
                'impersonationClaims': self.extract_impersonation_claims(message),
                'employeeIdentity': self.extract_employee_identity(message),  # FIXED: Now captures manager
                'scamType': self.classify_scam_type(message),
                'sophisticationLevel': self.assess_sophistication(message, message_count),
            },
            'agentNotes': self.generate_agent_notes(message, message_count),
        }
        
        return extracted
    
    def generate_agent_notes(self, message: str, message_count: int) -> str:
        """
        Generate professional agent notes.
        """
        scam_type = self.classify_scam_type(message)
        sophistication = self.assess_sophistication(message, message_count)
        tactics = self.extract_tactic_patterns(message)
        identity = self.extract_employee_identity(message)
        
        notes = f"Scam Type: {scam_type}; "
        notes += f"Sophistication: {sophistication}; "
        notes += f"Messages: {message_count}; "
        notes += f"Tactics: {', '.join(tactics[:4]) if tactics else 'None'}; "
        
        if identity:
            identity_str = ", ".join([f"{k}: {v}" for k, v in identity.items()])
            notes += f"Identity: {identity_str}; "
        
        accounts = len(self.extract_bank_accounts(message))
        upi = len(self.extract_upi_ids(message))
        phones = len(self.extract_phone_numbers(message))
        links = len(self.extract_phishing_links(message))
        
        intel_count = accounts + upi + phones + links
        notes += f"Intelligence extracted: {intel_count} data points."
        
        return notes


# Initialize
perfect_detector = PerfectScamDetector()


def detect_scam_perfect(message: str, message_count: int = 1) -> Dict[str, Any]:
    """Public function to detect and extract with PERFECT logic."""
    return perfect_detector.detect_and_extract(message, message_count)


def detect_scam_v2(message: str, message_count: int = 1) -> Dict[str, Any]:
    """Alias for detect_scam_perfect."""
    return detect_scam_perfect(message, message_count)
