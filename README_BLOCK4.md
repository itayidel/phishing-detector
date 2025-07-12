# Block 4: Flask API Service

## Overview
Block 4 is the Flask API Service that coordinates all detection modules and provides a web interface for email analysis. This allows other applications (like Gmail Add-on) to call our phishing detection system via HTTP requests.

## What Block 4 Does

### 🔧 **Coordinates Detection Modules**
- Takes raw email content via HTTP requests
- Calls Block 1 (Email Parser) to parse the email
- Calls Block 2 (Basic Detector) for rule-based detection
- Calls Block 3 (Pattern Detector) for advanced pattern matching
- Combines all results into a unified response

### 🌐 **Provides Web API Endpoints**
- `GET /api/health` - Health check endpoint
- `GET /api/version` - API version information
- `POST /api/scan` - Scan single email for phishing
- `POST /api/scan/batch` - Scan multiple emails at once

### 📊 **Returns Structured Results**
- Risk scores (0-100)
- Classifications (Safe, Suspicious, Phishing)
- Confidence levels
- Detailed explanations
- Module-specific results

## Files in Block 4

### 📁 Core Files
- `app.py` - Main Flask API server with all endpoints
- `models.py` - Data structures used by all modules
- `test_api.py` - Comprehensive test script
- `requirements.txt` - Updated with Flask dependencies

### 🔧 Dependencies
- Flask==2.3.3 (Web framework)
- flask-cors==4.0.0 (Cross-origin requests)
- All dependencies from Blocks 1-3

## How to Run Block 4

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Flask Server
```bash
python app.py
```

You should see:
```
🔍 Phishing Detection API Server
==================================================
Version: 1.0.0
Available endpoints:
  GET  /api/health      - Health check
  GET  /api/version     - Version info
  POST /api/scan        - Scan single email
  POST /api/scan/batch  - Scan multiple emails
==================================================
* Running on all addresses (0.0.0.0)
* Running on http://127.0.0.1:5000
* Running on http://[::1]:5000
```

### 3. Test the API
```bash
# In another terminal
python test_api.py
```

## API Usage Examples

### 🏥 Health Check
```bash
curl http://localhost:5000/api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "version": "1.0.0",
  "service": "Phishing Detection API"
}
```

### 📧 Scan Single Email
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "email_content": "From: security@paypal-fake.com\nSubject: URGENT: Verify account\nClick here: https://paypal-fake.com/verify",
    "options": {
      "include_basic": true,
      "include_patterns": true,
      "detailed_reasons": true
    }
  }'
```

**Response:**
```json
{
  "risk_score": 85,
  "classification": "Phishing",
  "confidence": 0.95,
  "scan_timestamp": "2024-01-15T10:30:00.000Z",
  "email_summary": {
    "sender": "security@paypal-fake.com",
    "subject": "URGENT: Verify account",
    "domains_found": ["paypal-fake.com"],
    "links_count": 1,
    "has_headers": true
  },
  "module_results": [
    {
      "module_name": "BasicDetector",
      "risk_score": 80,
      "classification": "Phishing",
      "confidence": 0.9,
      "reasons": [
        "Suspicious domain detected: paypal-fake.com",
        "Urgent language detected: urgent"
      ]
    },
    {
      "module_name": "PatternDetector", 
      "risk_score": 90,
      "classification": "Phishing",
      "confidence": 0.95,
      "reasons": [
        "Lookalike domain with character substitution: paypal-fake.com",
        "Credential harvesting phrase detected: 'verify account'"
      ]
    }
  ],
  "all_reasons": [
    "Suspicious domain detected: paypal-fake.com",
    "Urgent language detected: urgent",
    "Lookalike domain with character substitution: paypal-fake.com",
    "Credential harvesting phrase detected: 'verify account'"
  ]
}
```

### 📦 Batch Scan Multiple Emails
```bash
curl -X POST http://localhost:5000/api/scan/batch \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      {
        "id": "email_1",
        "content": "From: security@paypal-fake.com\nSubject: Urgent verification\nClick: https://paypal-fake.com"
      },
      {
        "id": "email_2",
        "content": "From: team@github.com\nSubject: Repository update\nYour repo was updated."
      }
    ],
    "options": {
      "include_basic": true,
      "include_patterns": true,
      "detailed_reasons": false
    }
  }'
```

## Code Architecture Explained

### 🏗️ **Flask Application Structure**
```python
# app.py - Main Flask application
from flask import Flask, request, jsonify
from flask_cors import CORS
import logging

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable cross-origin requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API endpoints
@app.route('/api/health', methods=['GET'])
def health_check():
    # Returns server status
    
@app.route('/api/scan', methods=['POST'])
def scan_email():
    # Main email scanning logic
    # 1. Validate request
    # 2. Parse email (Block 1)
    # 3. Run detections (Blocks 2-3)
    # 4. Combine results
    # 5. Return JSON response
```

### 📊 **Data Models**
```python
# models.py - Shared data structures
@dataclass
class EmailData:
    sender: str
    subject: str
    body: str
    links: List[str]
    domains: List[str]
    headers: Dict[str, str]
    timestamp: Optional[datetime]

@dataclass
class DetectionResult:
    risk_score: int          # 0-100
    classification: str      # "Safe", "Suspicious", "Phishing"
    confidence: float        # 0.0-1.0
    reasons: List[str]       # Explanations
    module_name: str         # Which detector
```

### 🔄 **Request Flow**
1. **HTTP Request** → Flask receives JSON request
2. **Validation** → Check required fields and data types
3. **Email Parsing** → Block 1 converts raw email to EmailData
4. **Detection** → Blocks 2-3 analyze EmailData
5. **Combination** → Merge results from all modules
6. **Response** → Return unified JSON response

## Key Features Explained

### 🛡️ **Error Handling**
- Validates all input data
- Handles module failures gracefully
- Returns helpful error messages
- Continues processing even if one module fails

### 📝 **Logging**
- Logs all API requests
- Tracks detection results
- Saves logs to file for debugging
- Includes timestamps and module names

### 🔧 **Flexible Options**
- Enable/disable specific detection modules
- Control level of detail in responses
- Batch processing for multiple emails
- Configurable response format

### 🌐 **CORS Support**
- Allows web browsers to call API
- Enables Gmail Add-on integration
- Handles preflight requests
- Supports cross-origin requests

## Testing Block 4

### 🧪 **Automated Testing**
```bash
python test_api.py
```

This runs comprehensive tests:
- Health check endpoint
- Version information
- Single email scanning
- Batch email scanning
- Error handling

### 🔍 **Manual Testing**
```bash
# Test health check
curl http://localhost:5000/api/health

# Test with suspicious email
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"email_content": "From: phisher@evil.com\nSubject: URGENT\nClick: https://evil.com"}'

# Test with legitimate email
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"email_content": "From: team@github.com\nSubject: Update\nYour repo was updated."}'
```

## Integration with Previous Blocks

### 🔗 **Block Dependencies**
- **Block 1 (Email Parser)**: Parses raw email content
- **Block 2 (Basic Detector)**: Provides rule-based detection
- **Block 3 (Pattern Detector)**: Provides advanced pattern matching
- **Block 4 (Flask API)**: Coordinates all modules via web API

### 📊 **Data Flow**
```
Raw Email → Block 1 → EmailData → Blocks 2-3 → DetectionResults → Block 4 → JSON Response
```

## What's Next

### 🚀 **Block 5: NLP Detection**
- Add natural language processing
- Sentiment analysis
- Grammar checking
- Text classification

### 🤖 **Block 6: LLM Integration**
- OpenAI/Hugging Face APIs
- AI-powered analysis
- Smart prompt engineering
- Fallback to local models

### 📱 **Block 8: Gmail Add-on**
- Google Apps Script
- Gmail API integration
- Real-time email scanning
- User-friendly interface

## Troubleshooting

### ❌ **Common Issues**

**"Module not found" errors:**
```bash
pip install -r requirements.txt
```

**"Connection refused" errors:**
```bash
# Make sure Flask server is running
python app.py
```

**"CORS" errors:**
```bash
# Flask-CORS should be installed
pip install flask-cors==4.0.0
```

### 🔧 **Debug Mode**
```bash
# Run Flask in debug mode
export FLASK_ENV=development
python app.py
```

## Summary

Block 4 successfully creates a production-ready Flask API that:
- ✅ Coordinates all detection modules
- ✅ Provides RESTful web endpoints
- ✅ Handles errors gracefully
- ✅ Supports batch processing
- ✅ Returns structured JSON responses
- ✅ Includes comprehensive logging
- ✅ Enables cross-origin requests
- ✅ Provides automated testing

This API can now be called by other applications (like Gmail Add-on) to analyze emails for phishing threats! 