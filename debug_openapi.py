import httpx
import asyncio

async def test_openapi():
    url = "http://127.0.0.1:8000/openapi.json"
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(url)
            print(f"Status: {r.status_code}")
            if r.status_code != 200:
                print(f"Response: {r.text}")
            else:
                print("OpenAPI JSON successfully fetched!")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_openapi())
