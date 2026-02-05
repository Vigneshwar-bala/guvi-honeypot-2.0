Session Schema (Frozen)

sessionId: string
turnCount: integer
conversationHistory:
  - sender: "scammer" | "user"
    text: string

extractedIntelligence:
  bankAccounts: list[string]
  upiIds: list[string]
  phishingLinks: list[string]
  phoneNumbers: list[string]
  suspiciousKeywords: list[string]

flags:
  readyForCallback: boolean

confidence: float
