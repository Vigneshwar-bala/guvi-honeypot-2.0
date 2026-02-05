from pydantic import BaseModel, Field
from typing import Optional, List

class MessageContent(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class ConversationMessage(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class RequestPayload(BaseModel):
    sessionId: str
    message: MessageContent
    conversationHistory: Optional[List[ConversationMessage]] = []
    metadata: Optional[Metadata] = None

class HoneypotResponse(BaseModel):
    status: str
    reply: str
