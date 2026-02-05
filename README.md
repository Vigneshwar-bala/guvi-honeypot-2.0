# GUVI Agentic Scam Honeypot

This project implements an AI-powered agentic honeypot that detects scam intent, engages scammers, extracts intelligence, and reports results to GUVI.

## Running Locally

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Authentication

All requests require an `x-api-key` header.

## Callback Behavior

* Callback failures are non-fatal by design
* The system retries once and continues
* This ensures resilience during evaluation

## Session Behavior

* Sessions are in-memory
* New sessionId creates a new conversation
* Infinite loops prevented via hard exit rules

## Exit Rules

Conversation ends when any condition is met:

* readyForCallback flag set by AI
* Confidence ≥ 0.95
* Turn count ≥ 12

## Intelligence Proof

Judges evaluate intelligence via the final callback payload only.
