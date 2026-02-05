# Deployment Guide

## Local Development Setup

### Step 1: Prerequisites
- Python 3.9+
- pip
- OpenRouter API key
- Git

### Step 2: Clone and Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/guvi-scam-honeypot-ai.git
cd guvi-scam-honeypot-ai

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Create .env file
cat > .env << EOF
OPENROUTER_API_KEY=your_actual_key_here
API_KEY=guvi-honeypot-demo-key
GUVI_CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
CALLBACK_TIMEOUT=5
EOF

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --reload --port 8000
```

### Step 3: Verify Installation

Open browser: http://127.0.0.1:8000/docs

You should see the Swagger UI with API documentation.

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_api.py -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| OPENROUTER_API_KEY | Your OpenRouter API key | Yes | N/A |
| API_KEY | API authentication key | No | guvi-honeypot-demo-key |
| GUVI_CALLBACK_URL | GUVI evaluation endpoint | No | https://hackathon.guvi.in/api/updateHoneyPotFinalResult |
| CALLBACK_TIMEOUT | Callback timeout in seconds | No | 5 |

## Cloud Deployment

### Option 1: Heroku

```bash
# Create Procfile
cat > Procfile << EOF
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
EOF

# Create runtime.txt
cat > runtime.txt << EOF
python-3.9.18
EOF

# Create .env.example (don't push actual keys)
cat > .env.example << EOF
OPENROUTER_API_KEY=your_api_key
API_KEY=guvi-honeypot-demo-key
GUVI_CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
CALLBACK_TIMEOUT=5
EOF

# Deploy
git push heroku main

# View logs
heroku logs --tail
```

### Option 2: Railway

1. Go to https://railway.app/
2. Click "New Project"
3. Select "GitHub Repo"
4. Connect your repository
5. Add environment variables in Railway dashboard
6. Deploy automatically on push

### Option 3: Render

1. Go to https://render.com/
2. Click "New +"
3. Select "Web Service"
4. Connect GitHub repository
5. Set build command: `pip install -r requirements.txt`
6. Set start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
7. Add environment variables
8. Deploy

## Health Check

Test if your deployment is working:

```bash
curl http://your-deployed-url/
# Should return: {"status": "ok", "message": "..."}
```

## Monitoring

### Local Logs
```bash
# Server logs appear in your terminal
# Look for [honeypot_message] logs
```

### Cloud Logs
- **Heroku:** `heroku logs --tail`
- **Railway:** Check Railway dashboard
- **Render:** Check Render dashboard

## API Testing After Deployment

```bash
curl -X 'POST' \
  'http://your-deployed-url/honeypot/message' \
  -H 'x-api-key: guvi-honeypot-demo-key' \
  -H 'Content-Type: application/json' \
  -d '{
  "sessionId": "test-001",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked",
    "timestamp": 1770282843745
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}'
```

Should return:
```json
{
  "status": "success",
  "reply": "That sounds serious. Which bank is this from?"
}
```

## Troubleshooting

### Port Already in Use
```bash
# Use different port
uvicorn app.main:app --reload --port 8001
```

### API Key Not Found
```bash
# Check .env file exists and has OPENROUTER_API_KEY
cat .env
```

### Import Errors
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

### OpenRouter Connection Failed
```bash
# Check API key is valid
# Check internet connection
# Check OpenRouter service status
```
