#!/usr/bin/env python3
"""
Test script for the AI URL Detector
This script demonstrates how the AI detector works with various URLs.
"""

import sys
import os
import json
import logging
from datetime import datetime

# Add the Blocks directory to the path so we can import our modules
sys.path.append('Blocks')

# Import our AI detector
from ai_detector import AIURLDetector, detect_ai_urls

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_ai_detector():
    """Test the AI URL detector with various URLs."""
    
    print("🔍 Testing AI URL Detector")
    print("=" * 50)
    
    # Test URLs - mix of suspicious and legitimate URLs
    test_urls = [
        # Suspicious URLs (should be classified as phishing)
        "http://secure-login-paypal.com/update/account-verification",
        "https://secure-banking-update.com/verify-account",
        "http://paypal-security-update.suspicious.com/login",
        "https://amazon-account-verification.phishing.com/update",
        "http://apple-id-locked.fake-site.com/unlock",
        
        # Legitimate URLs (should be classified as benign)
        "https://www.paypal.com/",
        "https://www.amazon.com/",
        "https://www.apple.com/",
        "https://www.google.com/",
        "https://www.wikipedia.org/",
        "https://github.com/",
        "https://stackoverflow.com/",
        
        # Edge cases
        "https://www.example.com/",
        "http://localhost:8080/",
        "ftp://files.example.com/",
    ]
    
    # Test individual URL prediction
    print("\n📊 Testing Individual URL Prediction")
    print("-" * 40)
    
    try:
        detector = AIURLDetector()
        
        if not detector.is_loaded:
            print("❌ AI model failed to load. Please check:")
            print("   - Make sure models/url_phishing_xgb_tiny.pkl exists")
            print("   - Install required dependencies: pip install -r requirements.txt")
            return False
        
        print("✅ AI model loaded successfully")
        print(f"📋 Model info: {detector.get_model_info()}")
        
        # Test a few individual URLs
        sample_urls = test_urls[:5]
        print(f"\nTesting {len(sample_urls)} sample URLs individually:")
        
        for url in sample_urls:
            prediction, probability = detector.predict_url(url)
            classification = "🚨 Phishing" if prediction == 1 else "✅ Benign"
            print(f"{classification:12} | {probability:.3f} | {url}")
        
        # Test batch prediction
        print(f"\n📦 Testing Batch URL Prediction")
        print("-" * 40)
        
        batch_results = detector.predict_urls(test_urls)
        
        print(f"Processed {len(batch_results)} URLs:")
        print(f"{'Classification':<12} | {'Prob':<5} | {'URL':<50}")
        print("-" * 70)
        
        phishing_count = 0
        benign_count = 0
        
        for url, result in batch_results.items():
            classification = result["classification"]
            probability = result["probability"]
            prediction = result["prediction"]
            
            if prediction == 1:
                phishing_count += 1
                emoji = "🚨"
            else:
                benign_count += 1
                emoji = "✅"
            
            print(f"{emoji} {classification:<10} | {probability:.3f} | {url[:50]}")
        
        print(f"\n📈 Summary:")
        print(f"   🚨 Phishing URLs: {phishing_count}")
        print(f"   ✅ Benign URLs: {benign_count}")
        print(f"   📊 Total URLs: {len(batch_results)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing AI detector: {str(e)}")
        logger.error(f"Test failed: {str(e)}")
        return False

def test_with_flask_integration():
    """Test the AI detector as it would be used in the Flask app."""
    
    print("\n🌐 Testing Flask Integration")
    print("=" * 50)
    
    try:
        # Simulate email data with links
        email_links = [
            "http://secure-login-paypal.com/update/account-verification",
            "https://www.paypal.com/",
            "https://suspicious-banking-site.com/login",
            "https://www.google.com/",
        ]
        
        print(f"📧 Simulating email with {len(email_links)} links:")
        for i, link in enumerate(email_links, 1):
            print(f"   {i}. {link}")
        
        # Test using the convenience function (as Flask app would)
        print("\n🔍 Running AI URL detection...")
        results = detect_ai_urls(email_links)
        
        # Format results as they would appear in Flask response
        flask_response = {
            "ai_url_analysis": results,
            "summary": {
                "total_urls": len(email_links),
                "phishing_urls": sum(1 for r in results.values() if r["prediction"] == 1),
                "benign_urls": sum(1 for r in results.values() if r["prediction"] == 0),
            }
        }
        
        print("\n📋 Flask API Response Format:")
        print(json.dumps(flask_response, indent=2))
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing Flask integration: {str(e)}")
        logger.error(f"Flask integration test failed: {str(e)}")
        return False

def main():
    """Main test function."""
    
    print("🚀 AI URL Detector Test Suite")
    print("=" * 50)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check if model file exists
    model_path = "models/url_phishing_xgb_tiny.pkl"
    if not os.path.exists(model_path):
        print(f"❌ Model file not found: {model_path}")
        print("   Please ensure the model file is in the models directory")
        return False
    
    # Run tests
    success = True
    success &= test_ai_detector()
    success &= test_with_flask_integration()
    
    print(f"\n🎯 Test Results:")
    if success:
        print("✅ All tests passed successfully!")
        print("\n💡 Next steps:")
        print("   1. Install dependencies: pip install -r requirements.txt")
        print("   2. Run the Flask app: python app.py")
        print("   3. Test the /api/scan endpoint with include_ai: true")
    else:
        print("❌ Some tests failed. Please check the error messages above.")
    
    print(f"⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 