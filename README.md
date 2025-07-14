# Phishing Email Detection System

A comprehensive phishing email detection system with multi-layered analysis capabilities and Gmail Add-on integration.

## 🚀 Features

- **Multi-Detection Engine**: Combines rule-based, pattern matching, NLP, and AI-powered detection
- **RESTful API**: Flask-based API for easy integration with external applications
- **Email Parser**: Extracts and analyzes email components (headers, body, links, domains)
- **Machine Learning**: XGBoost model for URL-based phishing detection
- **Gmail Integration**: Ready for Gmail Add-on deployment
- **Confidence Scoring**: Returns detailed risk scores with explanations

## 📋 Requirements

- Python 3.8+
- Flask 2.3+
- See `requirements.txt` for complete dependencies

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd upwind_task
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Download NLTK data** (first time only)
   ```python
   python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
   ```

## 🏃‍♂️ How to Run

### Start the API Server
```bash
python app.py
```

The server will start on `http://localhost:5000`

### API Endpoints
- `GET /api/health` - Health check
- `GET /api/version` - Version information  
- `POST /api/scan` - Scan single email
- `POST /api/scan/batch` - Scan multiple emails

### Example Usage

**Single Email Scan:**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "from": "suspicious@example.com",
    "subject": "Urgent: Verify your account NOW!",
    "body": "Click here to verify: http://phishing-site.com",
    "headers": {}
  }'
```

**Response:**
```json
{
  "is_phishing": true,
  "confidence_score": 85.4,
  "risk_level": "HIGH",
  "detections": {
    "basic": {"score": 75, "reasons": ["Urgent language detected"]},
    "pattern": {"score": 80, "reasons": ["Suspicious URL patterns"]},
    "nlp": {"score": 90, "reasons": ["Phishing language patterns"]},
    "ai": {"score": 95, "reasons": ["Malicious URL detected"]}
  }
}
```

## 🏗️ Project Structure

```
upwind_task/
├── app.py                 # Main Flask API server
├── Blocks/               # Detection modules
│   ├── email_parser.py   # Email parsing and extraction
│   ├── basic_detector.py # Rule-based detection
│   ├── pattern_detector.py # Advanced pattern matching
│   ├── nlp_detector.py   # NLP-based detection
│   └── ai_detector.py    # AI-powered URL detection
├── models.py             # Data models and structures
├── tests/                # Test files
└── url_phishing_xgb_tiny.pkl # Pre-trained ML model
```

## 🧪 Testing

Run individual tests:
```bash
python test_email_parser.py
python test_api.py
```

## 🔧 Configuration

- **Debug Mode**: Set `debug=False` in `app.py` for production
- **Port**: Change port in `app.run()` method
- **Logging**: Logs are saved to `phishing_detector.log`

## 📈 Detection Methods

1. **Basic Detection**: Domain validation, urgent language, sender reputation
2. **Pattern Matching**: Advanced regex patterns for phishing indicators  
3. **NLP Analysis**: Natural language processing for content analysis
4. **AI Detection**: Machine learning model for URL classification

## 🚀 Gmail Add-on Integration

This system is designed to work with a Gmail Add-on. The API endpoints can be called from Google Apps Script to provide real-time phishing detection within Gmail.

## ⚠️ Limitations

- Requires active internet connection for some detection modules
- ML model trained on specific URL patterns (may need retraining for new threats)
- Rate limiting not implemented (consider adding for production use)
