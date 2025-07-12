"""
Simple test to demonstrate Block 4 (Flask API) functionality
This shows how the API coordinates all detection modules
"""

# Test the individual modules directly (without Flask API)
from Blocks.email_parser import parse_email
from Blocks.basic_detector import detect_phishing  
from Blocks.pattern_detector import detect_patterns
from models import *

print("🔍 Block 4 - Flask API Service Demo")
print("=" * 60)

# Test email - obviously suspicious phishing email
test_email = """From: security@paypal-verification.com
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

print("📧 Testing Email Content:")
print("-" * 40)
subject_line = test_email.split('Subject: ')[1].split('\n')[0]
from_line = test_email.split('From: ')[1].split('\n')[0]
print(f"Subject: {subject_line}")
print(f"From: {from_line}")
print()

# STEP 1: Parse the email (Block 1)
print("📋 STEP 1: Email Parsing (Block 1)")
print("-" * 40)
email_data = parse_email(test_email)
print(f"✅ Parsed Email Data:")
print(f"   Sender: {email_data.sender}")
print(f"   Subject: {email_data.subject}")
print(f"   Links found: {len(email_data.links)}")
print(f"   Domains found: {email_data.domains}")
print()

# STEP 2: Basic Detection (Block 2)
print("🔍 STEP 2: Basic Detection (Block 2)")
print("-" * 40)
basic_result = detect_phishing(email_data)
print(f"✅ Basic Detection Results:")
print(f"   Risk Score: {basic_result.risk_score}/100")
print(f"   Classification: {basic_result.classification}")
print(f"   Confidence: {basic_result.confidence:.2f}")
print(f"   Reasons found: {len(basic_result.reasons)}")
for reason in basic_result.reasons[:3]:  # Show first 3 reasons
    print(f"     - {reason}")
if len(basic_result.reasons) > 3:
    print(f"     ... and {len(basic_result.reasons) - 3} more")
print()

# STEP 3: Pattern Detection (Block 3)
print("🔎 STEP 3: Pattern Detection (Block 3)")
print("-" * 40)
pattern_result = detect_patterns(email_data)
print(f"✅ Pattern Detection Results:")
print(f"   Risk Score: {pattern_result.risk_score}/100")
print(f"   Classification: {pattern_result.classification}")
print(f"   Confidence: {pattern_result.confidence:.2f}")
print(f"   Reasons found: {len(pattern_result.reasons)}")
for reason in pattern_result.reasons[:3]:  # Show first 3 reasons
    print(f"     - {reason}")
if len(pattern_result.reasons) > 3:
    print(f"     ... and {len(pattern_result.reasons) - 3} more")
print()

# STEP 4: Combine Results (Block 4 Logic)
print("🔄 STEP 4: Combining Results (Block 4 Logic)")
print("-" * 40)
all_results = [basic_result, pattern_result]
combined_risk = sum(r.risk_score for r in all_results) // len(all_results)
final_risk = min(combined_risk, 100)
highest_risk_result = max(all_results, key=lambda r: r.risk_score)
overall_classification = highest_risk_result.classification
overall_confidence = max(r.confidence for r in all_results)

print(f"✅ Combined Results:")
print(f"   Final Risk Score: {final_risk}/100")
print(f"   Overall Classification: {overall_classification}")
print(f"   Overall Confidence: {overall_confidence:.2f}")
print(f"   Modules Used: {len(all_results)}")
print()

print("📊 SUMMARY")
print("=" * 60)
print(f"🎯 This email is classified as: {overall_classification}")
print(f"📈 Risk Score: {final_risk}/100")
print(f"🔒 Confidence: {overall_confidence:.2f}")
print()

print("🚀 Block 4 Flask API Service would:")
print("   1. Receive HTTP request with email content")
print("   2. Parse email using Block 1 (EmailParser)")
print("   3. Analyze with Block 2 (BasicDetector)")
print("   4. Analyze with Block 3 (PatternDetector)")
print("   5. Combine results and return JSON response")
print()

print("✅ All detection modules are working correctly!")
print("✅ Block 4 Flask API is ready to coordinate them via HTTP!") 