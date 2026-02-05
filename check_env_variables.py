import os
from pathlib import Path
from dotenv import load_dotenv

print("=" * 80)
print("ENVIRONMENT VARIABLES DIAGNOSTIC")
print("=" * 80)

# Check 1: .env file exists
print("\n[CHECK 1] Does .env file exist?")
if Path(".env").exists():
    print("✅ .env file EXISTS at:", Path(".env").absolute())
    
    # Show contents
    print("\n.env file contents:")
    print("-" * 80)
    with open(".env", "r") as f:
        for line in f:
            if "API_KEY" in line or "KEY" in line:
                if "=" in line:
                    key_name = line.split("=")[0]
                    key_value = line.split("=")[1].strip()
                    # Show first 20 chars only
                    if len(key_value) > 20:
                        print(f"{key_name}={key_value[:20]}...")
                    else:
                        print(f"{key_name}={key_value}")
    print("-" * 80)
else:
    print("❌ .env file NOT FOUND!")
    print("   Create .env file in project root")

# Check 2: Load environment variables
print("\n[CHECK 2] Loading environment variables...")
load_dotenv()
print("✅ load_dotenv() called")

# Check 3: Check if OPENROUTER_API_KEY is set
print("\n[CHECK 3] Is OPENROUTER_API_KEY set?")
api_key = os.getenv("OPENROUTER_API_KEY")
if api_key:
    print(f"✅ OPENROUTER_API_KEY is set: {api_key[:20]}...")
else:
    print("❌ OPENROUTER_API_KEY is NOT set!")
    print("   Possible reasons:")
    print("   1. .env file doesn't have OPENROUTER_API_KEY line")
    print("   2. .env file has wrong key name (check spelling)")
    print("   3. .env file is in wrong location")

# Check 4: Check all environment variables
print("\n[CHECK 4] All environment variables with 'API' or 'KEY':")
for key, value in os.environ.items():
    if "API" in key.upper() or "KEY" in key.upper():
        if len(value) > 20:
            print(f"  {key}={value[:20]}...")
        else:
            print(f"  {key}={value}")

# Check 5: Check if openrouter_engine can initialize
print("\n[CHECK 5] Can openrouter_engine initialize?")
try:
    from app.modules.ai_agent.openrouter_engine import get_openrouter_engine
    print("✅ openrouter_engine module imports")
    
    try:
        engine = get_openrouter_engine()
        print("✅ GroqEngine initialized successfully")
    except ValueError as e:
        print(f"❌ GroqEngine initialization failed: {str(e)}")
        print("   → This means OPENROUTER_API_KEY is not in environment")
except ImportError as e:
    print(f"❌ openrouter_engine module import failed: {str(e)}")

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print("""
If OPENROUTER_API_KEY is NOT set:
1. Open .env file in project root
2. Make sure it has this line:
   OPENROUTER_API_KEY=sk-or-v1-your-actual-key-here
3. Replace with your actual OpenRouter API key
4. Save the file
5. Restart server
6. Run this diagnostic again
""")