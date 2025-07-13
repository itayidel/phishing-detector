"""
Flask API Service - Block 4
This is the web service that coordinates all detection modules.
Other applications (like Gmail Add-on) can call this API to analyze emails.
"""

# IMPORT SECTION - Getting all the tools we need
from flask import Flask, request, jsonify  # Flask web framework for creating API
from flask_cors import CORS  # CORS allows web browsers to call our API from different domains
import logging  # For tracking what happens in our API (debugging and monitoring)
import traceback  # For detailed error information when things go wrong
import json  # For handling JSON data (the format APIs use to communicate)
from datetime import datetime  # For timestamps in our logs and responses
from typing import Dict, List, Any  # For type hints to make our code clearer

# Import our detection modules that we built in previous blocks
from Blocks.email_parser import parse_email  # Block 1: Parses raw email into structured data
from Blocks.basic_detector import detect_phishing  # Block 2: Basic rule-based detection
from Blocks.pattern_detector import detect_patterns  # Block 3: Advanced pattern matching
from Blocks.nlp_detector import detect_nlp_patterns  # Block 5: NLP-based detection
from Blocks.ai_detector import detect_ai_urls  # Block 6: AI-powered URL detection
from models import EmailData, DetectionResult  # Our data structures

# CREATE THE FLASK APPLICATION
# Flask is the web framework that turns our Python code into a web service
app = Flask(__name__)

# ENABLE CORS (Cross-Origin Resource Sharing)
# This allows web browsers to call our API from different websites
# Without this, browsers would block calls from Gmail Add-on to our API
CORS(app)

# CONFIGURE LOGGING
# Logging helps us track what's happening in our API for debugging
# Set up basic logging configuration
logging.basicConfig(
    level=logging.INFO,  # Log INFO level and above (INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Log format with timestamp
    handlers=[
        logging.FileHandler('phishing_detector.log'),  # Save logs to file
        logging.StreamHandler()  # Also print logs to console
    ]
)

# Create a logger for this specific module
logger = logging.getLogger(__name__)

# API VERSION - helps track which version of our API is running
API_VERSION = "1.0.0"

# HEALTH CHECK ENDPOINT
# This endpoint lets other services check if our API is running properly
@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Simple health check endpoint to verify the API is running.
    This is useful for monitoring and debugging.
    
    Returns:
        JSON response with service status
    """
    # Log that someone checked our health
    logger.info("Health check requested")
    
    # Return a simple response showing we're alive and healthy
    return jsonify({
        'status': 'healthy',        # Simple status indicator
        'timestamp': datetime.now().isoformat(),  # When this health check happened
        'version': API_VERSION,     # Which version of our API is running
        'service': 'Phishing Detection API'  # What service this is
    }), 200  # HTTP 200 = OK/Success

# VERSION ENDPOINT
# This endpoint tells callers which version of our API they're talking to
@app.route('/api/version', methods=['GET'])
def get_version():
    """
    Returns the current API version.
    Useful for debugging and ensuring compatibility.
    
    Returns:
        JSON response with version information
    """
    # Log that someone asked for our version
    logger.info("Version information requested")
    
    # Return version details
    return jsonify({
        'version': API_VERSION,     # Current version number
        'name': 'Phishing Detection API',  # Service name
        'description': 'Multi-module phishing email detection service',  # What we do
        'modules': [               # List of detection modules we have
            'EmailParser',         # Block 1: Email parsing
            'BasicDetector',       # Block 2: Basic rule-based detection
            'PatternDetector',     # Block 3: Advanced pattern matching
            'NLPDetector',         # Block 5: NLP-based detection
            'AIDetector'           # Block 6: AI-powered URL detection
        ]
    }), 200  # HTTP 200 = OK/Success

# MAIN SCANNING ENDPOINT
# This is the core endpoint that analyzes emails for phishing
@app.route('/api/scan', methods=['POST'])
def scan_email():
    """
    Main endpoint to analyze an email for phishing indicators.
    
    Expected JSON input:
    {
        "email_content": "raw email content here...",
        "options": {
            "include_basic": true,     # Whether to run basic detection (optional)
            "include_patterns": true,  # Whether to run pattern detection (optional)
            "include_nlp": true,       # Whether to run NLP detection (optional)
            "include_ai": true,        # Whether to run AI URL detection (optional)
            "detailed_reasons": true   # Whether to include detailed explanations (optional)
        }
    }
    
    Returns:
        JSON response with detection results
    """
    # Log that we received a scan request
    logger.info("Email scan requested")
    
    try:
        # STEP 1: VALIDATE THE REQUEST
        # Check if we received valid JSON data
        if not request.is_json:
            # If request doesn't contain JSON, return error
            logger.error("Request is not JSON")
            return jsonify({
                'error': 'Request must be JSON',
                'message': 'Please send email content as JSON'
            }), 400  # HTTP 400 = Bad Request
        
        # Get the JSON data from the request
        data = request.get_json()
        
        # Check if required fields are present
        if not data or 'email_content' not in data:
            logger.error("Missing email_content in request")
            return jsonify({
                'error': 'Missing email_content',
                'message': 'Please provide email_content field in JSON'
            }), 400  # HTTP 400 = Bad Request
        
        # Extract the email content
        email_content = data['email_content']
        
        # Check if email content is not empty
        if not email_content or not isinstance(email_content, str):
            logger.error("Invalid email_content provided")
            return jsonify({
                'error': 'Invalid email_content',
                'message': 'email_content must be a non-empty string'
            }), 400  # HTTP 400 = Bad Request
        
        # STEP 2: PARSE OPTIONS
        # Get optional settings for the scan
        options = data.get('options', {})  # Default to empty dict if no options
        
        # Extract individual options with defaults
        include_basic = options.get('include_basic', True)      # Default: run basic detection
        include_patterns = options.get('include_patterns', True) # Default: run pattern detection
        include_nlp = options.get('include_nlp', True)          # Default: run NLP detection
        include_ai = options.get('include_ai', True)            # Default: run AI URL detection
        detailed_reasons = options.get('detailed_reasons', True) # Default: include detailed explanations
        
        # Log what options were requested
        logger.info(f"Scan options - Basic: {include_basic}, Patterns: {include_patterns}, NLP: {include_nlp}, AI: {include_ai}, Detailed: {detailed_reasons}")
        
        # STEP 3: PARSE THE EMAIL
        # Use Block 1 (EmailParser) to convert raw email into structured data
        logger.info("Parsing email content...")
        email_data = parse_email(email_content)
        
        # Log what we extracted from the email
        logger.info(f"Email parsed - Sender: {email_data.sender}, Subject: {email_data.subject[:50]}...")
        
        # STEP 4: INITIALIZE RESULTS COLLECTION
        # We'll collect results from all detection modules
        all_results = []        # List to store all detection results
        combined_risk_score = 0 # Total risk score from all modules
        max_confidence = 0.0    # Highest confidence from all modules
        all_reasons = []        # Combined reasons from all modules
        
        # STEP 5: RUN BASIC DETECTION (if requested)
        if include_basic:
            logger.info("Running basic detection...")
            try:
                # Call Block 2 (BasicDetector) to analyze the email
                basic_result = detect_phishing(email_data)
                
                # Add this result to our collection
                all_results.append(basic_result)
                
                # Update combined scores
                combined_risk_score += basic_result.risk_score
                max_confidence = max(max_confidence, basic_result.confidence)
                all_reasons.extend(basic_result.reasons)  # Add all reasons from basic detection
                
                # Log the basic detection results
                logger.info(f"Basic detection complete - Risk: {basic_result.risk_score}, Classification: {basic_result.classification}")
                
            except Exception as e:
                # If basic detection fails, log the error but continue
                logger.error(f"Basic detection failed: {str(e)}")
                # We don't return an error here because other modules might still work
        
        # STEP 6: RUN PATTERN DETECTION (if requested)
        if include_patterns:
            logger.info("Running pattern detection...")
            try:
                # Call Block 3 (PatternDetector) to analyze the email
                pattern_result = detect_patterns(email_data)
                
                # Add this result to our collection
                all_results.append(pattern_result)
                
                # Update combined scores
                combined_risk_score += pattern_result.risk_score
                max_confidence = max(max_confidence, pattern_result.confidence)
                all_reasons.extend(pattern_result.reasons)  # Add all reasons from pattern detection
                
                # Log the pattern detection results
                logger.info(f"Pattern detection complete - Risk: {pattern_result.risk_score}, Classification: {pattern_result.classification}")
                
            except Exception as e:
                # If pattern detection fails, log the error but continue
                logger.error(f"Pattern detection failed: {str(e)}")
                # We don't return an error here because other modules might still work
        
        # STEP 6.5: RUN NLP DETECTION (if requested)
        if include_nlp:
            logger.info("Running NLP detection...")
            try:
                # Call Block 5 (NLPDetector) to analyze the email
                nlp_result = detect_nlp_patterns(email_data)
                
                # Add this result to our collection
                all_results.append(nlp_result)
                
                # Update combined scores
                combined_risk_score += nlp_result.risk_score
                max_confidence = max(max_confidence, nlp_result.confidence)
                all_reasons.extend(nlp_result.reasons)  # Add all reasons from NLP detection
                
                # Log the NLP detection results
                logger.info(f"NLP detection complete - Risk: {nlp_result.risk_score}, Classification: {nlp_result.classification}")
                
            except Exception as e:
                # If NLP detection fails, log the error but continue
                logger.error(f"NLP detection failed: {str(e)}")
                # We don't return an error here because other modules might still work
        
        # STEP 6.6: RUN AI URL DETECTION (if requested)
        ai_url_results = {}
        if include_ai and email_data.links:
            logger.info("Running AI URL detection...")
            try:
                # Call Block 6 (AI Detector) to analyze URLs
                ai_url_results = detect_ai_urls(email_data.links)
                
                # Count how many URLs were classified as phishing
                phishing_urls = [url for url, result in ai_url_results.items() 
                               if result["prediction"] == 1]
                
                # Log the AI detection results
                logger.info(f"AI URL detection complete - {len(phishing_urls)} phishing URLs found out of {len(email_data.links)} total URLs")
                
            except Exception as e:
                # If AI detection fails, log the error but continue
                logger.error(f"AI URL detection failed: {str(e)}")
                ai_url_results = {}
        
        # STEP 7: CHECK IF WE HAVE ANY RESULTS
        if not all_results:
            # If no detection modules worked, return an error
            logger.error("All detection modules failed")
            return jsonify({
                'error': 'Detection failed',
                'message': 'All detection modules encountered errors'
            }), 500  # HTTP 500 = Internal Server Error
        
        # STEP 8: CALCULATE COMBINED RESULTS
        # Average the risk scores from all modules (don't just add them)
        avg_risk_score = combined_risk_score // len(all_results)
        
        # Make sure risk score doesn't exceed 100
        final_risk_score = min(avg_risk_score, 100)
        
        # Determine overall classification based on the highest risk
        # Find the module with the highest risk score
        highest_risk_result = max(all_results, key=lambda r: r.risk_score)
        overall_classification = highest_risk_result.classification
        
        # Use the highest confidence among all modules
        overall_confidence = max_confidence
        
        # STEP 9: BUILD THE RESPONSE
        # Create a comprehensive response with all the information
        response_data = {
            # OVERALL RESULTS
            'risk_score': final_risk_score,        # Combined risk score (0-100)
            'classification': overall_classification, # Overall classification
            'confidence': overall_confidence,       # Highest confidence
            'scan_timestamp': datetime.now().isoformat(),  # When this scan happened
            
            # EMAIL SUMMARY
            'email_summary': {
                'sender': email_data.sender,        # Who sent the email
                'subject': email_data.subject,      # Email subject
                'domains_found': email_data.domains, # Domains found in the email
                'links_count': len(email_data.links), # Number of links found
                'has_headers': bool(email_data.headers), # Whether we found email headers
            },
            
            # AI URL ANALYSIS (if available)
            'ai_url_analysis': ai_url_results if include_ai else None,
            
            # DETECTION MODULES RESULTS
            'module_results': []  # Results from each detection module
        }
        
        # Add results from each detection module
        for result in all_results:
            module_data = {
                'module_name': result.module_name,      # Which module created this result
                'risk_score': result.risk_score,        # Risk score from this module
                'classification': result.classification, # Classification from this module
                'confidence': result.confidence,        # Confidence from this module
            }
            
            # Add detailed reasons if requested
            if detailed_reasons:
                module_data['reasons'] = result.reasons
            else:
                # If detailed reasons not requested, just show count
                module_data['reasons_count'] = len(result.reasons)
            
            response_data['module_results'].append(module_data)
        
        # Add combined reasons if requested
        if detailed_reasons:
            response_data['all_reasons'] = all_reasons
        else:
            response_data['total_reasons_count'] = len(all_reasons)
        
        # STEP 10: LOG SUCCESS AND RETURN RESPONSE
        logger.info(f"Scan completed successfully - Final risk: {final_risk_score}, Classification: {overall_classification}")
        
        # Return the response with HTTP 200 (success)
        return jsonify(response_data), 200
        
    except Exception as e:
        # STEP 11: HANDLE UNEXPECTED ERRORS
        # If anything goes wrong that we didn't expect, log it and return error
        error_msg = str(e)
        error_trace = traceback.format_exc()  # Get detailed error information
        
        # Log the full error details
        logger.error(f"Unexpected error in scan_email: {error_msg}")
        logger.error(f"Full traceback: {error_trace}")
        
        # Return error response (don't expose internal details to client)
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred during email analysis',
            'timestamp': datetime.now().isoformat()
        }), 500  # HTTP 500 = Internal Server Error

# BATCH SCANNING ENDPOINT (BONUS)
# This endpoint allows scanning multiple emails at once
@app.route('/api/scan/batch', methods=['POST'])
def scan_batch():
    """
    Endpoint to scan multiple emails at once.
    
    Expected JSON input:
    {
        "emails": [
            {"id": "1", "content": "email 1 content..."},
            {"id": "2", "content": "email 2 content..."}
        ],
        "options": {
            "include_basic": true,
            "include_patterns": true,
            "include_nlp": true,
            "include_ai": true,
            "detailed_reasons": false
        }
    }
    
    Returns:
        JSON response with results for each email
    """
    logger.info("Batch scan requested")
    
    try:
        # Validate request
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        if not data or 'emails' not in data:
            return jsonify({'error': 'Missing emails array'}), 400
        
        emails = data['emails']
        options = data.get('options', {})
        
        # Validate emails array
        if not isinstance(emails, list) or len(emails) == 0:
            return jsonify({'error': 'emails must be a non-empty array'}), 400
        
        # Limit batch size to prevent overload
        if len(emails) > 10:
            return jsonify({'error': 'Batch size limited to 10 emails'}), 400
        
        # Process each email
        batch_results = []
        for email_item in emails:
            try:
                # Each email should have id and content
                if not isinstance(email_item, dict) or 'content' not in email_item:
                    batch_results.append({
                        'id': email_item.get('id', 'unknown'),
                        'error': 'Invalid email format - missing content'
                    })
                    continue
                
                email_id = email_item.get('id', f'email_{len(batch_results)}')
                email_content = email_item['content']
                
                # Create a request-like object for the single scan function
                # We'll reuse the logic from scan_email but adapt it for batch
                fake_request_data = {
                    'email_content': email_content,
                    'options': options
                }
                
                # Parse the email
                email_data = parse_email(email_content)
                
                # Run detections (simplified version of scan_email logic)
                all_results = []
                
                if options.get('include_basic', True):
                    try:
                        basic_result = detect_phishing(email_data)
                        all_results.append(basic_result)
                    except Exception as e:
                        logger.error(f"Basic detection failed for email {email_id}: {str(e)}")
                
                if options.get('include_patterns', True):
                    try:
                        pattern_result = detect_patterns(email_data)
                        all_results.append(pattern_result)
                    except Exception as e:
                        logger.error(f"Pattern detection failed for email {email_id}: {str(e)}")
                
                if options.get('include_nlp', True):
                    try:
                        nlp_result = detect_nlp_patterns(email_data)
                        all_results.append(nlp_result)
                    except Exception as e:
                        logger.error(f"NLP detection failed for email {email_id}: {str(e)}")
                
                # AI URL detection for batch processing
                ai_url_results = {}
                if options.get('include_ai', True) and email_data.links:
                    try:
                        ai_url_results = detect_ai_urls(email_data.links)
                        logger.info(f"AI URL detection completed for email {email_id}")
                    except Exception as e:
                        logger.error(f"AI URL detection failed for email {email_id}: {str(e)}")
                
                if all_results:
                    # Calculate combined results
                    combined_risk = sum(r.risk_score for r in all_results) // len(all_results)
                    final_risk = min(combined_risk, 100)
                    highest_risk_result = max(all_results, key=lambda r: r.risk_score)
                    
                    # Build result for this email
                    email_result = {
                        'id': email_id,
                        'risk_score': final_risk,
                        'classification': highest_risk_result.classification,
                        'confidence': max(r.confidence for r in all_results),
                        'sender': email_data.sender,
                        'subject': email_data.subject,
                        'ai_url_analysis': ai_url_results if options.get('include_ai', True) else None
                    }
                    
                    # Add detailed reasons if requested
                    if options.get('detailed_reasons', False):
                        all_reasons = []
                        for result in all_results:
                            all_reasons.extend(result.reasons)
                        email_result['reasons'] = all_reasons
                    
                    batch_results.append(email_result)
                else:
                    # No detection modules worked
                    batch_results.append({
                        'id': email_id,
                        'error': 'All detection modules failed'
                    })
                    
            except Exception as e:
                # Error processing this specific email
                batch_results.append({
                    'id': email_item.get('id', 'unknown'),
                    'error': f'Processing failed: {str(e)}'
                })
        
        # Return batch results
        logger.info(f"Batch scan completed - {len(batch_results)} emails processed")
        return jsonify({
            'results': batch_results,
            'total_processed': len(batch_results),
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Batch scan error: {str(e)}")
        return jsonify({
            'error': 'Batch scan failed',
            'message': str(e)
        }), 500

# ERROR HANDLERS
# These functions handle common HTTP errors and return nice JSON responses

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors (page not found)."""
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested endpoint does not exist',
        'available_endpoints': [
            'GET /api/health',
            'GET /api/version', 
            'POST /api/scan (includes NLP and AI URL analysis)',
            'POST /api/scan/batch'
        ]
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors (method not allowed)."""
    return jsonify({
        'error': 'Method not allowed',
        'message': 'The HTTP method is not allowed for this endpoint'
    }), 405

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors (internal server error)."""
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

# MAIN FUNCTION
# This runs when the script is executed directly
if __name__ == '__main__':
    # Log that we're starting the server
    logger.info("Starting Phishing Detection API server...")
    
    # Print startup information
    print("=" * 50)
    print("🔍 Phishing Detection API Server")
    print("=" * 50)
    print(f"Version: {API_VERSION}")
    print("Available endpoints:")
    print("  GET  /api/health      - Health check")
    print("  GET  /api/version     - Version info")
    print("  POST /api/scan        - Scan single email")
    print("  POST /api/scan/batch  - Scan multiple emails")
    print("=" * 50)
    
    # Start the Flask development server
    # In production, you'd use a proper WSGI server like gunicorn
    app.run(
        host='0.0.0.0',    # Listen on all network interfaces
        port=5000,         # Port number
        debug=True,        # Enable debug mode (auto-reload on code changes)
        threaded=True      # Handle multiple requests simultaneously
    ) 