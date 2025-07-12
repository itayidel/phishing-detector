# Phishing Email Detection System - Design Document

## Project Overview

This system detects phishing emails using a progressive approach from simple rule-based detection to advanced ML techniques, integrated with a Gmail Add-on for real-world usage.

### What the Interviewers Want to Test
- **System Design**: Breaking complex problems into manageable components
- **Code Quality**: Clean, modular, well-documented Python code
- **Integration Skills**: Connecting backend services with Gmail Add-on
- **Progressive Implementation**: Starting simple and adding complexity
- **Real-world Application**: Building functional software that actually works

## Architecture Overview

```
[Gmail Add-on] → [Flask API] → [Detection Engine] → [Multiple Detection Modules]
```

## Development Strategy: Independent Building Blocks

### Phase 1: Foundation (Essential - Start Here)
**Block 1: Email Parser Module**
- Input: Raw email content (headers, body, attachments info)
- Output: Structured email data (sender, subject, body, links, domains)
- Dependencies: None
- Time: ~30 minutes
- Skills Demonstrated: Data parsing, basic Python structure

**Block 2: Basic Rule-Based Detection**
- Input: Parsed email data
- Output: Risk score (0-100) with explanations
- Features: Suspicious domains, urgent keywords, sender validation
- Dependencies: Block 1
- Time: ~45 minutes
- Skills Demonstrated: Logic implementation, heuristics

### Phase 2: Enhanced Detection (Important)
**Block 3: Advanced Pattern Matching**
- Input: Parsed email data
- Output: Enhanced risk analysis
- Features: Regex patterns, URL analysis, header inspection
- Dependencies: Block 1, 2
- Time: ~45 minutes
- Skills Demonstrated: Regular expressions, pattern recognition

**Block 4: Flask API Service**
- Input: HTTP requests with email data
- Output: JSON responses with detection results
- Features: RESTful API, error handling, logging
- Dependencies: Blocks 1-3
- Time: ~30 minutes
- Skills Demonstrated: Web services, API design

### Phase 3: Advanced Features (If Time Permits)
**Block 5: NLP-Based Detection**
- Input: Email text content
- Output: Language-based risk indicators
- Features: Sentiment analysis, urgency detection, text classification
- Dependencies: Block 1
- Time: ~60 minutes
- Skills Demonstrated: Natural language processing

**Block 6: Free LLM API Integration**
- Input: Email content
- Output: AI-powered phishing analysis
- Features: OpenAI/Hugging Face API calls, prompt engineering
- Dependencies: Block 4
- Time: ~45 minutes
- Skills Demonstrated: AI integration, API usage

**Block 7: Simple ML Model (Optional)**
- Input: Email features
- Output: ML-based classification
- Features: Feature extraction, basic classifier (Naive Bayes/SVM)
- Dependencies: Blocks 1-3
- Time: ~90 minutes
- Skills Demonstrated: Machine learning basics

### Phase 4: Integration (Final)
**Block 8: Gmail Add-on**
- Input: Gmail email selection
- Output: In-Gmail phishing results
- Features: Google Apps Script, Gmail API, UI components
- Dependencies: Block 4
- Time: ~60 minutes
- Skills Demonstrated: Google APIs, frontend integration

## Technical Stack

### Backend (Python)
```
Flask==2.3.3
requests==2.31.0
beautifulsoup4==4.12.2
nltk==3.8.1
scikit-learn==1.3.0
pandas==2.0.3
numpy==1.24.3
python-dotenv==1.0.0
validators==0.20.0
textblob==0.17.1
```

### Frontend
- Google Apps Script (JavaScript)
- Gmail Add-on HTML/CSS

## Detailed Block Specifications

### Block 1: Email Parser (`email_parser.py`)
```python
class EmailParser:
    def parse(self, raw_email: str) -> EmailData:
        # Extract headers, body, links, attachments
        pass
```
**Output**: Clean data structure with sender, subject, body, links, domains

### Block 2: Basic Rule-Based Detection (`basic_detector.py`)
```python
class BasicDetector:
    def analyze(self, email_data: EmailData) -> DetectionResult:
        # Check suspicious domains, urgent keywords, sender patterns
        pass
```
**Rules**: 
- Suspicious domains (bit.ly, tinyurl, etc.)
- Urgent keywords ("urgent", "immediate action", "verify account")
- Sender domain mismatches
- Generic greetings

### Block 3: Advanced Pattern Matching (`pattern_detector.py`)
```python
class PatternDetector:
    def analyze(self, email_data: EmailData) -> DetectionResult:
        # Regex patterns, URL analysis, header inspection
        pass
```
**Features**:
- URL shortener detection
- Lookalike domain analysis
- Email header spoofing detection
- Phone number/SSN pattern matching

### Block 4: Flask API Service (`app.py`)
```python
@app.route('/api/scan', methods=['POST'])
def scan_email():
    # Coordinate all detection modules
    # Return unified results
    pass
```
**Endpoints**:
- `POST /api/scan` - Analyze email
- `GET /api/health` - Service status
- `GET /api/version` - API version

### Block 5: NLP-Based Detection (`nlp_detector.py`)
```python
class NLPDetector:
    def analyze(self, email_data: EmailData) -> DetectionResult:
        # Sentiment analysis, urgency detection
        pass
```
**Features**:
- Sentiment analysis (negative urgency)
- Emotional manipulation detection
- Grammar/spelling analysis
- Language authenticity check

### Block 6: LLM API Integration (`llm_detector.py`)
```python
class LLMDetector:
    def analyze(self, email_data: EmailData) -> DetectionResult:
        # Call free AI APIs for analysis
        pass
```
**Implementation**:
- Use Hugging Face Inference API (free tier)
- Prompt engineering for phishing detection
- Fallback to local models if API fails

### Block 7: ML Model (`ml_detector.py`)
```python
class MLDetector:
    def analyze(self, email_data: EmailData) -> DetectionResult:
        # Feature extraction and classification
        pass
```
**Features**:
- TF-IDF vectorization
- Naive Bayes classifier
- Training on public phishing datasets

### Block 8: Gmail Add-on (`gmail_addon.gs`)
```javascript
function scanCurrentEmail() {
    // Get current email content
    // Call Flask API
    // Display results in sidebar
}
```

## Data Structures

### EmailData
```python
@dataclass
class EmailData:
    sender: str
    subject: str
    body: str
    links: List[str]
    domains: List[str]
    headers: Dict[str, str]
    timestamp: datetime
```

### DetectionResult
```python
@dataclass
class DetectionResult:
    risk_score: int  # 0-100
    classification: str  # "Safe", "Suspicious", "Phishing"
    confidence: float  # 0.0-1.0
    reasons: List[str]  # Explanation of findings
    module_name: str  # Which detector generated this
```

## Testing Strategy

### Unit Tests (Per Block)
- `test_email_parser.py` - Test email parsing accuracy
- `test_basic_detector.py` - Test rule-based logic
- `test_pattern_detector.py` - Test regex patterns
- `test_api.py` - Test Flask endpoints

### Integration Tests
- End-to-end email processing
- API response validation
- Gmail Add-on functionality

### Test Data
- Known phishing emails (from public datasets)
- Legitimate emails for false positive testing
- Edge cases (malformed emails, empty content)

## Deployment & Demo

### Local Development
```bash
pip install -r requirements.txt
python app.py
# Test with curl/Postman
```

### Demo Script
1. Show basic rule detection with obvious phishing email
2. Demonstrate API endpoints with different email types
3. Show Gmail Add-on scanning a real email
4. Explain each detection module's contribution

## Success Metrics

### Technical Criteria
- **Accuracy**: >80% detection rate on test emails
- **False Positives**: <10% on legitimate emails
- **Performance**: <3 seconds response time
- **Code Quality**: Clean, documented, modular structure

### Interview Demonstration
- Clear explanation of each component
- Logical progression from simple to complex
- Working integration with Gmail
- Understanding of real-world limitations

## Future Enhancements (Beyond Interview)
- Database storage for email history
- User feedback integration
- Advanced ML models (BERT, transformers)
- Real-time threat intelligence feeds
- Multi-language support

## Key Implementation Notes

1. **Start Simple**: Begin with Block 1 and 2 - they provide immediate value
2. **Independent Blocks**: Each module can be developed and tested separately
3. **Progressive Enhancement**: Add complexity only after basics work
4. **Documentation**: Comment every function for easy explanation
5. **Error Handling**: Graceful failures in each component
6. **Logging**: Track what each detector finds for debugging

This design allows you to have a working system after implementing just the first 4 blocks, with each subsequent block adding more sophistication. Perfect for time-constrained development and easy to explain in an interview setting. 