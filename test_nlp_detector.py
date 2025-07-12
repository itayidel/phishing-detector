"""
Test script for the NLP Detector (Block 5)
Tests the Natural Language Processing capabilities for phishing detection.
"""

from Blocks.email_parser import parse_email
from Blocks.nlp_detector import detect_nlp_patterns

def test_nlp_detector():
    """Test the NLP detector with various email samples."""
    
    print("🔍 Testing NLP Detector (Block 5)")
    print("=" * 50)
    
    # TEST 1: Emotionally manipulative phishing email
    print("\n📧 TEST 1: Emotionally Manipulative Email")
    print("-" * 40)
    
    phishing_email = """From: security-alert@bank-urgent.com
Subject: URGENT!!! Account SUSPENDED - ACT NOW OR LOSE EVERYTHING!!!

Dear valued customer,

We are writing to inform you that your account has been compromised and will be permanently suspended unless you take immediate action. This is a final warning!

Kindly revert back to us with your complete account details. You must act now! Do not delay! If you don't respond within 24 hours, you will lose access to your account forever and all your money will be gone.

This is very urgent matter. Please help us to verify your identity immediately. Time is running out!

Thanks and regards,
Security Department
"""
    
    # Parse and analyze
    email_data = parse_email(phishing_email)
    result = detect_nlp_patterns(email_data)
    
    print(f"📊 Risk Score: {result.risk_score}/100")
    print(f"🏷️  Classification: {result.classification}")
    print(f"🎯 Confidence: {result.confidence:.2f}")
    print("📋 NLP Analysis Results:")
    for reason in result.reasons:
        print(f"   • {reason}")
    
    # TEST 2: Legitimate business email
    print("\n📧 TEST 2: Legitimate Business Email")
    print("-" * 40)
    
    legitimate_email = """From: notifications@amazon.com
Subject: Your Order Confirmation

Hello,

Thank you for your recent order. We're pleased to confirm that your order #123456 has been received and is being processed.

Your order details:
- Item: Wireless Headphones
- Quantity: 1
- Total: $49.99

We will send you a shipping confirmation email once your order ships, typically within 1-2 business days.

If you have any questions about your order, please contact our customer service team.

Best regards,
Amazon Customer Service Team
"""
    
    # Parse and analyze
    email_data = parse_email(legitimate_email)
    result = detect_nlp_patterns(email_data)
    
    print(f"📊 Risk Score: {result.risk_score}/100")
    print(f"🏷️  Classification: {result.classification}")
    print(f"🎯 Confidence: {result.confidence:.2f}")
    print("📋 NLP Analysis Results:")
    for reason in result.reasons:
        print(f"   • {reason}")
    
    # TEST 3: Financial scam email
    print("\n📧 TEST 3: Financial Scam Email")
    print("-" * 40)
    
    financial_scam = """From: lottery-winner@global-lottery.com
Subject: Congratulations! You have won $5,000,000 in the International Lottery!

Dear winner,

Congratulations! You have won the sum of Five Million Dollars ($5,000,000) in our international lottery. This is not a joke!

To claim your prize, you must kindly revert back to us with your personal information including your bank account details. You must also pay a processing fee of $500 to release your winnings.

This is a limited time offer. Act now before someone else claims your prize! Don't miss this opportunity of a lifetime.

Hope you are fine and looking forward to hearing from you.

Thanks and regards,
Lottery Commission
"""
    
    # Parse and analyze
    email_data = parse_email(financial_scam)
    result = detect_nlp_patterns(email_data)
    
    print(f"📊 Risk Score: {result.risk_score}/100")
    print(f"🏷️  Classification: {result.classification}")
    print(f"🎯 Confidence: {result.confidence:.2f}")
    print("📋 NLP Analysis Results:")
    for reason in result.reasons:
        print(f"   • {reason}")
    
    print("\n✅ NLP Detector testing complete!")
    print("=" * 50)

if __name__ == "__main__":
    test_nlp_detector() 