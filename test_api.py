"""
API Test Script - Testing Block 4 (Flask API Service)
This script demonstrates how to use the Flask API to scan emails for phishing.
Run this after starting the Flask server to test all endpoints.
"""

import requests  # For making HTTP requests to our API
import json      # For handling JSON data
import time      # For adding delays between requests

# API Configuration
# These settings tell us where our Flask API is running
API_BASE_URL = "http://localhost:5000"  # Where our Flask server is running
API_ENDPOINTS = {
    'health': f"{API_BASE_URL}/api/health",         # Health check endpoint
    'version': f"{API_BASE_URL}/api/version",       # Version information endpoint
    'scan': f"{API_BASE_URL}/api/scan",             # Single email scan endpoint
    'batch': f"{API_BASE_URL}/api/scan/batch"       # Batch email scan endpoint
}

def test_health_endpoint():
    """
    Test the health check endpoint.
    This verifies that our API server is running and responding.
    """
    print("🏥 Testing Health Check Endpoint...")
    print("=" * 50)
    
    try:
        # Make a GET request to the health endpoint
        response = requests.get(API_ENDPOINTS['health'])
        
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            print("✅ Health check passed!")
            print(f"   Status: {data.get('status')}")
            print(f"   Service: {data.get('service')}")
            print(f"   Version: {data.get('version')}")
            print(f"   Timestamp: {data.get('timestamp')}")
            return True
        else:
            print(f"❌ Health check failed with status code: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to API server!")
        print("   Make sure the Flask server is running (python app.py)")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False

def test_version_endpoint():
    """
    Test the version information endpoint.
    This gets details about our API version and available modules.
    """
    print("\n📋 Testing Version Endpoint...")
    print("=" * 50)
    
    try:
        # Make a GET request to the version endpoint
        response = requests.get(API_ENDPOINTS['version'])
        
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            print("✅ Version information retrieved!")
            print(f"   API Version: {data.get('version')}")
            print(f"   Name: {data.get('name')}")
            print(f"   Description: {data.get('description')}")
            print(f"   Available Modules: {', '.join(data.get('modules', []))}")
            return True
        else:
            print(f"❌ Version endpoint failed with status code: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing version endpoint: {str(e)}")
        return False

def test_scan_endpoint():
    """
    Test the main email scanning endpoint.
    This tests the core functionality of our phishing detection system.
    """
    print("\n🔍 Testing Email Scan Endpoint...")
    print("=" * 50)
    
    # Test email 1: Obviously suspicious phishing email
    suspicious_email = """From: security@paypal-verification.com
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
    
    # Test email 2: Legitimate-looking email
    legitimate_email = """From: notifications@github.com
Subject: New repository starred
Date: Mon, 15 Jan 2024 10:30:00 -0800

Hello,

Someone starred your repository "awesome-project" on GitHub.

You can view your repository at: https://github.com/user/awesome-project

Best regards,
The GitHub Team
"""
    
    # Test cases with different emails and options
    test_cases = [
        {
            'name': 'Suspicious Phishing Email',
            'email': suspicious_email,
            'options': {
                'include_basic': True,
                'include_patterns': True,
                'detailed_reasons': True
            }
        },
        {
            'name': 'Legitimate Email',
            'email': legitimate_email,
            'options': {
                'include_basic': True,
                'include_patterns': True,
                'detailed_reasons': True
            }
        },
        {
            'name': 'Basic Detection Only',
            'email': suspicious_email,
            'options': {
                'include_basic': True,
                'include_patterns': False,
                'detailed_reasons': False
            }
        }
    ]
    
    # Test each case
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n📧 Test Case {i}: {test_case['name']}")
        print("-" * 40)
        
        try:
            # Prepare the request data
            request_data = {
                'email_content': test_case['email'],
                'options': test_case['options']
            }
            
            # Make a POST request to the scan endpoint
            response = requests.post(
                API_ENDPOINTS['scan'],
                json=request_data,  # Send data as JSON
                headers={'Content-Type': 'application/json'}
            )
            
            # Check if the request was successful
            if response.status_code == 200:
                # Parse the JSON response
                data = response.json()
                
                print("✅ Scan completed successfully!")
                print(f"   Risk Score: {data.get('risk_score')}/100")
                print(f"   Classification: {data.get('classification')}")
                print(f"   Confidence: {data.get('confidence'):.2f}")
                
                # Show email summary
                email_summary = data.get('email_summary', {})
                print(f"   Email From: {email_summary.get('sender')}")
                print(f"   Subject: {email_summary.get('subject')}")
                print(f"   Links Found: {email_summary.get('links_count')}")
                print(f"   Domains Found: {email_summary.get('domains_found')}")
                
                # Show module results
                module_results = data.get('module_results', [])
                print(f"   Modules Used: {len(module_results)}")
                for module in module_results:
                    print(f"     - {module.get('module_name')}: {module.get('risk_score')}/100")
                
                # Show reasons if detailed
                if test_case['options'].get('detailed_reasons'):
                    reasons = data.get('all_reasons', [])
                    if reasons:
                        print(f"   Reasons Found: {len(reasons)}")
                        for reason in reasons[:3]:  # Show first 3 reasons
                            print(f"     - {reason}")
                        if len(reasons) > 3:
                            print(f"     ... and {len(reasons) - 3} more")
                
            else:
                print(f"❌ Scan failed with status code: {response.status_code}")
                print(f"   Error: {response.text}")
                
        except Exception as e:
            print(f"❌ Error testing scan endpoint: {str(e)}")
        
        # Add a small delay between tests
        time.sleep(0.5)

def test_batch_endpoint():
    """
    Test the batch email scanning endpoint.
    This tests scanning multiple emails at once.
    """
    print("\n📦 Testing Batch Scan Endpoint...")
    print("=" * 50)
    
    # Prepare batch of emails to test
    batch_emails = [
        {
            'id': 'email_1',
            'content': """From: security@paypal-fake.com
Subject: Urgent account verification required
Please verify your account: https://paypal-fake.com/verify"""
        },
        {
            'id': 'email_2', 
            'content': """From: team@github.com
Subject: Weekly repository digest
Here's your weekly summary from GitHub."""
        },
        {
            'id': 'email_3',
            'content': """From: admin@bank-security.tk
Subject: LOCKED: Immediate action required
Your account will be deleted: https://bit.ly/fakebanklink"""
        }
    ]
    
    try:
        # Prepare the request data
        request_data = {
            'emails': batch_emails,
            'options': {
                'include_basic': True,
                'include_patterns': True,
                'detailed_reasons': False  # Keep response smaller for batch
            }
        }
        
        # Make a POST request to the batch endpoint
        response = requests.post(
            API_ENDPOINTS['batch'],
            json=request_data,
            headers={'Content-Type': 'application/json'}
        )
        
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            
            print("✅ Batch scan completed successfully!")
            print(f"   Total Processed: {data.get('total_processed')}")
            print(f"   Timestamp: {data.get('timestamp')}")
            
            # Show results for each email
            results = data.get('results', [])
            for result in results:
                print(f"\n   📧 Email {result.get('id')}:")
                if 'error' in result:
                    print(f"     ❌ Error: {result.get('error')}")
                else:
                    print(f"     Risk Score: {result.get('risk_score')}/100")
                    print(f"     Classification: {result.get('classification')}")
                    print(f"     Confidence: {result.get('confidence'):.2f}")
                    print(f"     From: {result.get('sender')}")
                    print(f"     Subject: {result.get('subject')}")
                    
        else:
            print(f"❌ Batch scan failed with status code: {response.status_code}")
            print(f"   Error: {response.text}")
            
    except Exception as e:
        print(f"❌ Error testing batch endpoint: {str(e)}")

def test_error_handling():
    """
    Test error handling by sending invalid requests.
    This ensures our API handles bad requests gracefully.
    """
    print("\n🚨 Testing Error Handling...")
    print("=" * 50)
    
    # Test cases for error handling
    error_test_cases = [
        {
            'name': 'Missing email_content',
            'data': {'options': {'include_basic': True}},
            'expected_status': 400
        },
        {
            'name': 'Empty email_content',
            'data': {'email_content': ''},
            'expected_status': 400
        },
        {
            'name': 'Invalid JSON',
            'data': 'this is not json',
            'expected_status': 400
        },
        {
            'name': 'Non-string email_content',
            'data': {'email_content': 123},
            'expected_status': 400
        }
    ]
    
    for test_case in error_test_cases:
        print(f"\n🧪 Testing: {test_case['name']}")
        print("-" * 30)
        
        try:
            # Send request with invalid data
            if isinstance(test_case['data'], str):
                # Send invalid JSON
                response = requests.post(
                    API_ENDPOINTS['scan'],
                    data=test_case['data'],
                    headers={'Content-Type': 'application/json'}
                )
            else:
                # Send invalid but valid JSON
                response = requests.post(
                    API_ENDPOINTS['scan'],
                    json=test_case['data'],
                    headers={'Content-Type': 'application/json'}
                )
            
            # Check if we got the expected error status
            if response.status_code == test_case['expected_status']:
                print("✅ Error handled correctly!")
                
                # Try to parse error response
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data.get('error')}")
                    print(f"   Message: {error_data.get('message')}")
                except:
                    print(f"   Raw response: {response.text}")
            else:
                print(f"❌ Expected status {test_case['expected_status']}, got {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error during error test: {str(e)}")

def main():
    """
    Main function to run all API tests.
    This runs through all our test cases to verify the API works correctly.
    """
    print("🚀 Starting Flask API Tests")
    print("=" * 60)
    print("Make sure the Flask server is running first!")
    print("Run: python app.py")
    print("=" * 60)
    
    # Track test results
    test_results = []
    
    # Run all tests
    test_results.append(("Health Check", test_health_endpoint()))
    test_results.append(("Version Info", test_version_endpoint()))
    test_results.append(("Email Scanning", test_scan_endpoint()))
    test_results.append(("Batch Scanning", test_batch_endpoint()))
    test_results.append(("Error Handling", test_error_handling()))
    
    # Show summary
    print("\n" + "=" * 60)
    print("🏁 Test Results Summary")
    print("=" * 60)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        if result:
            print(f"✅ {test_name}: PASSED")
            passed += 1
        else:
            print(f"❌ {test_name}: FAILED")
    
    print(f"\n📊 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your Flask API is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main() 