import re

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
        elif any(w in msg_lower for w in ["lottery", "prize", "won", "winner"]):
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
