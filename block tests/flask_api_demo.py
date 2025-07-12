"""
Flask API Demo - Interactive Testing of Block 4
This script demonstrates how to use the Flask API endpoints step by step.
Each test shows what the API receives and returns.
"""

import requests
import json
import time
from datetime import datetime

# API Configuration
API_BASE_URL = "http://localhost:5000"

def print_separator(title):
    """Print a nice separator for each test section."""
    print("\n" + "=" * 70)
    print(f"🔍 {title}")
    print("=" * 70)

def print_subsection(title):
    """Print a subsection header."""
    print(f"\n📋 {title}")
    print("-" * 50)

def pretty_print_json(data, indent=2):
    """Pretty print JSON data with proper formatting."""
    print(json.dumps(data, indent=indent, ensure_ascii=False))

def test_health_endpoint():
    """
    TEST 1: Health Check Endpoint
    This endpoint tells us if the API server is running properly.
    """
    print_separator("TEST 1: Health Check Endpoint")
    
    print("🏥 What this endpoint does:")
    print("   - Checks if the Flask API server is running")
    print("   - Returns basic server information")
    print("   - No input required (GET request)")
    
    print_subsection("Making Request")
    url = f"{API_BASE_URL}/api/health"
    print(f"📤 GET {url}")
    
    try:
        response = requests.get(url)
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("📥 Response Data:")
            pretty_print_json(data)
            
            print("\n✅ What this tells us:")
            print(f"   - Server Status: {data.get('status')}")
            print(f"   - API Version: {data.get('version')}")
            print(f"   - Service Name: {data.get('service')}")
            print(f"   - Timestamp: {data.get('timestamp')}")
            
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

def test_version_endpoint():
    """
    TEST 2: Version Information Endpoint
    This endpoint tells us what detection modules are available.
    """
    print_separator("TEST 2: Version Information Endpoint")
    
    print("📋 What this endpoint does:")
    print("   - Returns API version information")
    print("   - Lists available detection modules")
    print("   - Useful for checking compatibility")
    
    print_subsection("Making Request")
    url = f"{API_BASE_URL}/api/version"
    print(f"📤 GET {url}")
    
    try:
        response = requests.get(url)
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("📥 Response Data:")
            pretty_print_json(data)
            
            print("\n✅ What this tells us:")
            print(f"   - API Version: {data.get('version')}")
            print(f"   - Description: {data.get('description')}")
            print(f"   - Available Modules: {', '.join(data.get('modules', []))}")
            
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

def test_scan_endpoint_phishing():
    """
    TEST 3: Scan Endpoint with Phishing Email
    This is the main endpoint - it analyzes emails for phishing.
    """
    print_separator("TEST 3: Scan Endpoint - Phishing Email")
    
    print("🔍 What this endpoint does:")
    print("   - Receives email content via POST request")
    print("   - Runs all detection modules (Blocks 1-3)")
    print("   - Returns combined risk assessment")
    print("   - Provides detailed explanations")
    
    # Create a suspicious phishing email for testing
    phishing_email = """From: security@paypal-verification.com
Subject: URGENT: Account suspended - verify now!
Return-Path: noreply@suspicious-domain.tk

Dear customer,

Your account has been suspended due to unusual activity.
Click here immediately to verify: https://paypal-secure.tk/verify?token=abc123&user=victim

You must provide your:
- Username and password
- Social Security Number: 123-45-6789
- Credit card number
- Phone number: (555) 123-4567

You must act within 24 hours or your account will be permanently closed.

PayPal Security Team (Not really PayPal)
"""
    
    print_subsection("Email Content Being Analyzed")
    print("📧 This is a DELIBERATELY SUSPICIOUS email for testing:")
    print("   - Fake PayPal sender")
    print("   - Urgent language ('URGENT', 'immediately')")
    print("   - Suspicious domain (paypal-secure.tk)")
    print("   - Requests sensitive info (SSN, credit card)")
    print("   - URL shortener (.tk domain)")
    
    print_subsection("Making Request")
    url = f"{API_BASE_URL}/api/scan"
    request_data = {
        "email_content": phishing_email,
        "options": {
            "include_basic": True,
            "include_patterns": True,
            "detailed_reasons": True
        }
    }
    
    print(f"📤 POST {url}")
    print("📤 Request Data:")
    print(f"   - email_content: {len(phishing_email)} characters")
    print(f"   - include_basic: {request_data['options']['include_basic']}")
    print(f"   - include_patterns: {request_data['options']['include_patterns']}")
    print(f"   - detailed_reasons: {request_data['options']['detailed_reasons']}")
    
    try:
        response = requests.post(url, json=request_data)
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("📥 Response Data:")
            pretty_print_json(data)
            
            print("\n✅ Analysis Results:")
            print(f"   🎯 Final Classification: {data.get('classification')}")
            print(f"   📊 Risk Score: {data.get('risk_score')}/100")
            print(f"   🔒 Confidence: {data.get('confidence'):.2f}")
            print(f"   📧 Email From: {data.get('email_summary', {}).get('sender')}")
            print(f"   📧 Subject: {data.get('email_summary', {}).get('subject')}")
            print(f"   🔗 Links Found: {data.get('email_summary', {}).get('links_count')}")
            print(f"   🌐 Domains: {data.get('email_summary', {}).get('domains_found')}")
            
            print("\n🔍 Detection Modules Results:")
            for module in data.get('module_results', []):
                print(f"   - {module.get('module_name')}: {module.get('risk_score')}/100 ({module.get('classification')})")
            
            print("\n🚨 Reasons Found:")
            for i, reason in enumerate(data.get('all_reasons', [])[:5], 1):
                print(f"   {i}. {reason}")
            
            total_reasons = len(data.get('all_reasons', []))
            if total_reasons > 5:
                print(f"   ... and {total_reasons - 5} more reasons")
            
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

def test_scan_endpoint_legitimate():
    """
    TEST 4: Scan Endpoint with Legitimate Email
    Test the API with a normal, safe email to see the difference.
    """
    print_separator("TEST 4: Scan Endpoint - Legitimate Email")
    
    print("✅ What this test shows:")
    print("   - How the API handles legitimate emails")
    print("   - Comparison with phishing email results")
    print("   - False positive detection")
    
    # Create a legitimate email for testing
    legitimate_email = """From: notifications@github.com
Subject: New repository starred
Date: Mon, 15 Jan 2024 10:30:00 -0800

Hello,

Someone starred your repository "awesome-project" on GitHub.

You can view your repository at: https://github.com/user/awesome-project

Best regards,
The GitHub Team
"""
    
    print_subsection("Email Content Being Analyzed")
    print("📧 This is a LEGITIMATE email for comparison:")
    print("   - Real GitHub sender")
    print("   - Normal subject (no urgency)")
    print("   - Legitimate domain (github.com)")
    print("   - No sensitive info requests")
    print("   - Professional tone")
    
    print_subsection("Making Request")
    url = f"{API_BASE_URL}/api/scan"
    request_data = {
        "email_content": legitimate_email,
        "options": {
            "include_basic": True,
            "include_patterns": True,
            "detailed_reasons": True
        }
    }
    
    print(f"📤 POST {url}")
    print("📤 Request Data:")
    print(f"   - email_content: {len(legitimate_email)} characters")
    
    try:
        response = requests.post(url, json=request_data)
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("📥 Response Data:")
            pretty_print_json(data)
            
            print("\n✅ Analysis Results:")
            print(f"   🎯 Final Classification: {data.get('classification')}")
            print(f"   📊 Risk Score: {data.get('risk_score')}/100")
            print(f"   🔒 Confidence: {data.get('confidence'):.2f}")
            
            print("\n🔍 Detection Modules Results:")
            for module in data.get('module_results', []):
                print(f"   - {module.get('module_name')}: {module.get('risk_score')}/100 ({module.get('classification')})")
            
            reasons = data.get('all_reasons', [])
            if reasons:
                print(f"\n⚠️  Reasons Found ({len(reasons)}):")
                for i, reason in enumerate(reasons[:3], 1):
                    print(f"   {i}. {reason}")
            else:
                print("\n✅ No suspicious patterns found!")
            
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

def test_batch_endpoint():
    """
    TEST 5: Batch Scan Endpoint
    Test scanning multiple emails at once.
    """
    print_separator("TEST 5: Batch Scan Endpoint")
    
    print("📦 What this endpoint does:")
    print("   - Scans multiple emails in one request")
    print("   - More efficient than individual requests")
    print("   - Returns results for each email")
    
    # Create multiple emails for batch testing
    emails = [
        {
            "id": "email_1_phishing",
            "content": """From: security@paypal-fake.com
Subject: Urgent account verification required
Please verify your account immediately: https://paypal-fake.com/verify"""
        },
        {
            "id": "email_2_legitimate",
            "content": """From: team@github.com
Subject: Weekly repository digest
Here's your weekly summary from GitHub."""
        },
        {
            "id": "email_3_suspicious",
            "content": """From: admin@bank-security.tk
Subject: LOCKED: Immediate action required
Your account will be deleted: https://bit.ly/fakebanklink"""
        }
    ]
    
    print_subsection("Batch Content Being Analyzed")
    print("📧 Testing with 3 different emails:")
    print("   1. Phishing email (fake PayPal)")
    print("   2. Legitimate email (real GitHub)")
    print("   3. Suspicious email (fake bank with URL shortener)")
    
    print_subsection("Making Request")
    url = f"{API_BASE_URL}/api/scan/batch"
    request_data = {
        "emails": emails,
        "options": {
            "include_basic": True,
            "include_patterns": True,
            "detailed_reasons": False  # Keep response smaller for batch
        }
    }
    
    print(f"📤 POST {url}")
    print(f"📤 Request Data: {len(emails)} emails")
    
    try:
        response = requests.post(url, json=request_data)
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("📥 Response Data:")
            pretty_print_json(data)
            
            print("\n✅ Batch Results:")
            print(f"   📊 Total Processed: {data.get('total_processed')}")
            print(f"   ⏰ Timestamp: {data.get('timestamp')}")
            
            print("\n🔍 Individual Email Results:")
            for result in data.get('results', []):
                print(f"\n   📧 {result.get('id')}:")
                if 'error' in result:
                    print(f"     ❌ Error: {result.get('error')}")
                else:
                    print(f"     🎯 Classification: {result.get('classification')}")
                    print(f"     📊 Risk Score: {result.get('risk_score')}/100")
                    print(f"     🔒 Confidence: {result.get('confidence'):.2f}")
                    print(f"     📧 From: {result.get('sender')}")
                    print(f"     📧 Subject: {result.get('subject')}")
            
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

def test_error_handling():
    """
    TEST 6: Error Handling
    Test how the API handles invalid requests.
    """
    print_separator("TEST 6: Error Handling")
    
    print("🚨 What this test shows:")
    print("   - How the API handles invalid requests")
    print("   - Error messages and status codes")
    print("   - API robustness")
    
    # Test cases for error handling
    error_tests = [
        {
            "name": "Missing email_content",
            "data": {"options": {"include_basic": True}},
            "expected": "Should return 400 - Bad Request"
        },
        {
            "name": "Empty email_content",
            "data": {"email_content": ""},
            "expected": "Should return 400 - Bad Request"
        },
        {
            "name": "Invalid email_content type",
            "data": {"email_content": 123},
            "expected": "Should return 400 - Bad Request"
        }
    ]
    
    url = f"{API_BASE_URL}/api/scan"
    
    for i, test in enumerate(error_tests, 1):
        print_subsection(f"Error Test {i}: {test['name']}")
        print(f"📤 POST {url}")
        print(f"📤 Request Data: {test['data']}")
        print(f"🎯 Expected: {test['expected']}")
        
        try:
            response = requests.post(url, json=test['data'])
            print(f"📥 Response Status: {response.status_code}")
            
            if response.status_code == 400:
                error_data = response.json()
                print("📥 Error Response:")
                pretty_print_json(error_data)
                print("✅ Error handled correctly!")
            else:
                print(f"⚠️  Unexpected status code: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Request Error: {e}")

def main():
    """
    Main function to run all Flask API tests.
    This gives you a complete understanding of how Block 4 works.
    """
    print("🚀 Flask API Demo - Block 4 Testing")
    print("=" * 70)
    print("This demo shows you how Block 4 (Flask API) coordinates all detection modules.")
    print("Make sure the Flask server is running: python app.py")
    print()
    
    # Run all tests
    test_health_endpoint()
    time.sleep(1)
    
    test_version_endpoint()
    time.sleep(1)
    
    test_scan_endpoint_phishing()
    time.sleep(1)
    
    test_scan_endpoint_legitimate()
    time.sleep(1)
    
    test_batch_endpoint()
    time.sleep(1)
    
    test_error_handling()
    
    # Summary
    print_separator("SUMMARY - What You Learned")
    print("🎓 You now understand how Block 4 Flask API works:")
    print("   ✅ Health check endpoint - Server status")
    print("   ✅ Version endpoint - API information")
    print("   ✅ Scan endpoint - Main email analysis")
    print("   ✅ Batch endpoint - Multiple email analysis")
    print("   ✅ Error handling - Robust request validation")
    print()
    print("🔍 Block 4 coordinates all detection modules:")
    print("   📋 Block 1 (EmailParser) - Parses email structure")
    print("   🔍 Block 2 (BasicDetector) - Rule-based detection")
    print("   🔎 Block 3 (PatternDetector) - Advanced pattern matching")
    print("   🌐 Block 4 (Flask API) - Web service coordination")
    print()
    print("🎯 Ready for real-world usage:")
    print("   - Gmail Add-on can call these endpoints")
    print("   - Other applications can integrate")
    print("   - Scalable and robust architecture")

if __name__ == "__main__":
    main() 