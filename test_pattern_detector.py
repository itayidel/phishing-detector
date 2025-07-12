"""
Test script to demonstrate Block 3 (Pattern Detector) working with Blocks 1 and 2.
This shows how all three blocks work together to detect sophisticated phishing emails.
"""

from email_parser import parse_email
from basic_detector import detect_phishing
from pattern_detector import detect_patterns


def test_sophisticated_phishing():
    """Test a sophisticated phishing email that Block 3 should catch."""
    
    # This is a sophisticated phishing email with multiple advanced techniques
    sophisticated_email = """From: security@paypaI.com
Subject: Account Verification Required
Return-Path: noreply@suspicious-domain.tk

Dear Customer,

We detected suspicious login activity on your account. Please verify your credentials immediately.

Click here to verify: https://paypal-verify.tk/login?token=abc123&verify=true&user=victim&redirect=account

To complete verification, please provide:
- Username and password
- Social Security Number: 123-45-6789
- Credit card number: 4532-1234-5678-9012
- Phone number: (555) 123-4567

Download our security app: https://secure-paypal.tk/security.exe

If you don't verify within 24 hours, your account will be permanently suspended.

Security Team
PayPal Security Department
"""
    
    print("=== SOPHISTICATED PHISHING EMAIL TEST ===")
    print("Testing email with advanced phishing techniques...")
    print()
    
    # STEP 1: Parse the email (Block 1)
    print("STEP 1: Parsing email with Block 1 (Email Parser)")
    email_data = parse_email(sophisticated_email)
    print(f"✓ Parsed email from: {email_data.sender}")
    print(f"✓ Found {len(email_data.links)} links")
    print(f"✓ Found {len(email_data.domains)} domains: {email_data.domains}")
    print()
    
    # STEP 2: Run basic detection (Block 2)
    print("STEP 2: Running Block 2 (Basic Detector)")
    basic_result = detect_phishing(email_data)
    print(f"✓ Basic Risk Score: {basic_result.risk_score}/100")
    print(f"✓ Basic Classification: {basic_result.classification}")
    print("✓ Basic Reasons:")
    for reason in basic_result.reasons:
        print(f"   - {reason}")
    print()
    
    # STEP 3: Run advanced pattern detection (Block 3)
    print("STEP 3: Running Block 3 (Pattern Detector)")
    pattern_result = detect_patterns(email_data)
    print(f"✓ Pattern Risk Score: {pattern_result.risk_score}/100")
    print(f"✓ Pattern Classification: {pattern_result.classification}")
    print("✓ Pattern Reasons:")
    for reason in pattern_result.reasons:
        print(f"   - {reason}")
    print()
    
    # STEP 4: Show how the blocks complement each other
    print("STEP 4: Comparison of Detection Methods")
    print("=" * 60)
    print(f"Block 2 (Basic):   {basic_result.risk_score:3d}/100 - {basic_result.classification}")
    print(f"Block 3 (Pattern): {pattern_result.risk_score:3d}/100 - {pattern_result.classification}")
    print(f"Combined Confidence: {(basic_result.confidence + pattern_result.confidence) / 2:.2f}")
    print()
    
    # Show what each block caught
    print("What Block 2 caught:")
    for reason in basic_result.reasons[:3]:  # Show first 3 reasons
        print(f"   • {reason}")
    print()
    
    print("What Block 3 caught additionally:")
    for reason in pattern_result.reasons[:3]:  # Show first 3 reasons
        print(f"   • {reason}")
    print()


def test_legitimate_email():
    """Test a legitimate email to ensure we don't get false positives."""
    
    legitimate_email = """From: notifications@github.com
Subject: Your pull request has been merged
Date: Mon, 15 Jan 2024 10:30:00 -0800

Hi Developer,

Your pull request #123 "Fix bug in user authentication" has been successfully merged into the main branch.

View the merged PR: https://github.com/company/repo/pull/123

Thanks for your contribution!

Best regards,
GitHub Team
"""
    
    print("\n=== LEGITIMATE EMAIL TEST ===")
    print("Testing legitimate email to check for false positives...")
    print()
    
    # Parse and analyze
    email_data = parse_email(legitimate_email)
    basic_result = detect_phishing(email_data)
    pattern_result = detect_patterns(email_data)
    
    print(f"Email from: {email_data.sender}")
    print(f"Subject: {email_data.subject}")
    print()
    
    print("Detection Results:")
    print(f"Block 2 (Basic):   {basic_result.risk_score:3d}/100 - {basic_result.classification}")
    print(f"Block 3 (Pattern): {pattern_result.risk_score:3d}/100 - {pattern_result.classification}")
    print()
    
    if basic_result.risk_score < 40 and pattern_result.risk_score < 40:
        print("✓ SUCCESS: Both detectors correctly identified this as safe!")
    else:
        print("⚠ WARNING: False positive detected!")
        print("Basic reasons:", basic_result.reasons)
        print("Pattern reasons:", pattern_result.reasons)


if __name__ == "__main__":
    test_sophisticated_phishing()
    test_legitimate_email()
    
    print("\n=== SUMMARY ===")
    print("Block 3 (Pattern Detector) adds advanced capabilities:")
    print("• Regex pattern matching for sensitive info requests")
    print("• Sophisticated URL analysis (shorteners, file extensions)")
    print("• Lookalike domain detection with character substitution")
    print("• Email header spoofing analysis")
    print("• Credential harvesting detection")
    print("• Suspicious TLD identification")
    print("• Advanced URL parameter analysis")
    print("\nThis makes it much harder for sophisticated phishing emails to slip through!") 