const axios = require('axios');

async function testApiKey() {
    const API_URL = 'http://127.0.0.1:8000/honeypot/message';
    const API_KEY = 'guvi-honeypot-demo-key';

    const testPayload = {
        sessionId: "test-session-001",
        message: {
            sender: "scammer",
            text: "Test message to verify API key authentication",
            timestamp: Date.now()
        },
        conversationHistory: [],
        metadata: {
            channel: "SMS",
            language: "English",
            locale: "IN"
        }
    };

    try {
        console.log('Testing API key authentication...');
        console.log('API URL:', API_URL);
        console.log('API Key:', API_KEY);
        console.log('Payload:', JSON.stringify(testPayload, null, 2));

        const response = await axios.post(API_URL, testPayload, {
            headers: {
                'x-api-key': API_KEY,
                'Content-Type': 'application/json',
                'accept': 'application/json'
            }
        });

        console.log('\n✅ SUCCESS: API key authentication works!');
        console.log('Status Code:', response.status);
        console.log('Response:', JSON.stringify(response.data, null, 2));

    } catch (error) {
        if (error.response) {
            console.log('\n❌ FAILED: API key authentication failed');
            console.log('Status Code:', error.response.status);
            console.log('Error Response:', JSON.stringify(error.response.data, null, 2));
        } else if (error.request) {
            console.log('\n❌ FAILED: No response received from server');
            console.log('Error:', error.message);
        } else {
            console.log('\n❌ FAILED: Request setup error');
            console.log('Error:', error.message);
        }
    }
}

// Run the test
testApiKey();
