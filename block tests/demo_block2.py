"""
Demo script for Block 2 - Basic Rule-Based Detection
Shows how the detector analyzes emails and assigns risk scores.
"""

from email_parser import parse_email
from basic_detector import detect_phishing


def demo_phishing_detection():
    """Demo the complete flow: Parse email → Detect phishing → Show results"""
    
    print("🔍 BLOCK 2 DEMONSTRATION - BASIC PHISHING DETECTION")
    print("="*60)
    print("This shows how we detect phishing using simple rules and patterns\n")
    
    # Example 1: Obvious phishing email
    print("📧 EXAMPLE 1: Obvious Phishing Email")
    print("-" * 40)
    
    phishing_email = """From: security@paypal-verification.com
Subject: URGENT: Account suspended - verify immediately!

Dear customer,

Your account has been suspended due to unusual activity.
Click here immediately to verify: https://secure-paypal.malicious-site.com/verify

You must act within 24 hours or your account will be permanently closed.

PayPal Security Team
"""
    
    print("📥 Raw Email:")
    print(phishing_email)
    
    # Step 1: Parse the email (Block 1)
    email_data = parse_email(phishing_email)
    print("\n📊 After Block 1 (Parsing):")
    print(f"  Sender: {email_data.sender}")
    print(f"  Subject: {email_data.subject}")
    print(f"  Links: {email_data.links}")
    print(f"  Domains: {email_data.domains}")
    
    # Step 2: Detect phishing (Block 2)
    result = detect_phishing(email_data)
    print(f"\n🎯 After Block 2 (Detection):")
    print(f"  Risk Score: {result.risk_score}/100")
    print(f"  Classification: {result.classification}")
    print(f"  Confidence: {result.confidence:.1%}")
    print(f"  Reasons Found:")
    for reason in result.reasons:
        print(f"    • {reason}")
    
    print("\n" + "="*60 + "\n")
    
    # Example 2: Legitimate email
    print("📧 EXAMPLE 2: Legitimate Email")
    print("-" * 40)
    
    legitimate_email = """From: notifications@github.com
Subject: New pull request opened

Hello John,

A new pull request has been opened in your repository:
https://github.com/yourcompany/project/pull/123

Please review when you have time.

Best regards,
GitHub Team
"""
    
    print("📥 Raw Email:")
    print(legitimate_email)
    
    # Parse and analyze
    email_data = parse_email(legitimate_email)
    result = detect_phishing(email_data)
    
    print(f"\n🎯 Detection Results:")
    print(f"  Risk Score: {result.risk_score}/100")
    print(f"  Classification: {result.classification}")
    print(f"  Confidence: {result.confidence:.1%}")
    if result.reasons:
        print(f"  Reasons:")
        for reason in result.reasons:
            print(f"    • {reason}")
    else:
        print("  No suspicious patterns detected!")
    
    print("\n" + "="*60 + "\n")
    
    # Example 3: Borderline suspicious email
    print("📧 EXAMPLE 3: Borderline Suspicious Email")
    print("-" * 40)
    
    suspicious_email = """From: support@company-update.com
Subject: Action required: Update your information

Dear valued customer,

Please update your payment information to continue service.
Click here: https://bit.ly/update-info

Thank you for your attention to this matter.
"""
    
    print("📥 Raw Email:")
    print(suspicious_email)
    
    # Parse and analyze
    email_data = parse_email(suspicious_email)
    result = detect_phishing(email_data)
    
    print(f"\n🎯 Detection Results:")
    print(f"  Risk Score: {result.risk_score}/100")
    print(f"  Classification: {result.classification}")
    print(f"  Confidence: {result.confidence:.1%}")
    print(f"  Reasons:")
    for reason in result.reasons:
        print(f"    • {reason}")


def explain_how_it_works():
    """Explain the detection logic step by step."""
    print("\n🧠 HOW THE DETECTION WORKS:")
    print("="*50)
    print("Block 2 runs 6 different tests on every email:")
    print()
    print("TEST 1: Suspicious Domains (0-35 points each)")
    print("  • Checks for URL shorteners (bit.ly, tinyurl.com)")
    print("  • Looks for fake domains (secure-paypal.com)")
    print("  • Detects lookalike domains (paypal-security.com)")
    print()
    print("TEST 2: Urgent Language (0-30 points)")
    print("  • Counts urgent words (urgent, immediate, suspended)")
    print("  • Checks for ALL CAPS in subject")
    print("  • More urgent words = higher risk")
    print()
    print("TEST 3: Sender Legitimacy (0-25 points)")
    print("  • Compares sender domain with link domains")
    print("  • Checks for suspicious sender patterns")
    print("  • Detects generic addresses (admin@, support@)")
    print()
    print("TEST 4: Generic Greetings (0-10 points)")
    print("  • Looks for 'Dear Customer' instead of real names")
    print("  • Mass phishing emails use generic greetings")
    print()
    print("TEST 5: Suspicious URLs (0-30 points)")
    print("  • Checks for IP addresses instead of domains")
    print("  • Looks for suspicious keywords in URLs")
    print("  • Detects unusually long URLs")
    print()
    print("TEST 6: Link Density (0-15 points)")
    print("  • Counts total number of links")
    print("  • Calculates link-to-text ratio")
    print("  • Too many links = spam indicator")
    print()
    print("FINAL SCORING:")
    print("  • 0-39 points: Safe (probably legitimate)")
    print("  • 40-69 points: Suspicious (needs attention)")
    print("  • 70-100 points: Phishing (very dangerous)")


if __name__ == "__main__":
    demo_phishing_detection()
    explain_how_it_works()
    
    print("\n🎉 Block 2 is complete and working!")
    print("Ready to move to Block 3 (Advanced Pattern Matching)? 🚀") 