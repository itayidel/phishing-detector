"""
Demo script for Block 1 - Email Parser
Shows exactly what input we work with and what gets extracted.
"""

from email_parser import parse_email
import json


def demo_phishing_email():
    """Demo with a typical phishing email."""
    print("🔍 DEMO 1: Typical Phishing Email")
    print("="*50)
    
    # This is the RAW INPUT - what we receive
    raw_input = """From: security@paypal-verification.com
To: victim@company.com
Subject: URGENT: Account Security Alert - Action Required
Date: Wed, 13 Dec 2023 10:30:00 +0000

Dear PayPal Customer,

We have detected unusual activity on your account. Your account has been 
temporarily suspended for your security.

To restore access immediately, please verify your information by clicking 
the secure link below:

https://paypal-secure-verification.suspicious-domain.com/verify?id=12345

You must complete this verification within 24 hours or your account will 
be permanently closed.

Thank you for your prompt attention to this matter.

PayPal Security Team
"""
    
    print("📥 RAW INPUT:")
    print(raw_input)
    print("\n" + "="*50)
    
    # Parse the email
    result = parse_email(raw_input)
    
    print("📤 PARSED OUTPUT:")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Links Found: {len(result.links)}")
    for i, link in enumerate(result.links, 1):
        print(f"  Link {i}: {link}")
    print(f"Domains Extracted: {result.domains}")
    print(f"Headers: {len(result.headers)} headers found")
    for key, value in result.headers.items():
        print(f"  {key}: {value}")
    print(f"Timestamp: {result.timestamp}")
    print(f"Body Length: {len(result.body)} characters")
    print()


def demo_plain_text():
    """Demo with just plain text (no headers)."""
    print("🔍 DEMO 2: Plain Text Message")
    print("="*50)
    
    # Raw input without proper email headers
    raw_input = """Your bank account has been compromised!

Please click here immediately to secure your account:
https://secure-banking.fake-bank.com/login

This is urgent and cannot wait. Act now!

Contact us: 1-800-FAKE-BANK
"""
    
    print("📥 RAW INPUT:")
    print(raw_input)
    print("\n" + "="*50)
    
    # Parse the email
    result = parse_email(raw_input)
    
    print("📤 PARSED OUTPUT:")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Links Found: {len(result.links)}")
    for i, link in enumerate(result.links, 1):
        print(f"  Link {i}: {link}")
    print(f"Domains Extracted: {result.domains}")
    print(f"Headers: {len(result.headers)} headers found")
    print()


def demo_legitimate_email():
    """Demo with a legitimate email for comparison."""
    print("🔍 DEMO 3: Legitimate Email")
    print("="*50)
    
    raw_input = """From: notifications@github.com
To: developer@company.com
Subject: New pull request opened
Date: Wed, 13 Dec 2023 15:45:00 +0000

Hello,

A new pull request has been opened in your repository:

Repository: company/awesome-project
Title: Fix authentication bug
URL: https://github.com/company/awesome-project/pull/123

Please review when you have a chance.

Best regards,
GitHub Team
"""
    
    print("📥 RAW INPUT:")
    print(raw_input)
    print("\n" + "="*50)
    
    # Parse the email
    result = parse_email(raw_input)
    
    print("📤 PARSED OUTPUT:")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Links Found: {len(result.links)}")
    for i, link in enumerate(result.links, 1):
        print(f"  Link {i}: {link}")
    print(f"Domains Extracted: {result.domains}")
    print(f"Headers: {len(result.headers)} headers found")
    print()


def show_data_structure():
    """Show the actual data structure we create."""
    print("🔍 DEMO 4: Data Structure Details")
    print("="*50)
    
    raw_input = """From: test@example.com
Subject: Test

Visit https://example.com and https://google.com
"""
    
    result = parse_email(raw_input)
    
    print("📤 COMPLETE EmailData OBJECT:")
    print(f"Type: {type(result)}")
    print(f"Fields available:")
    print(f"  - sender: '{result.sender}'")
    print(f"  - subject: '{result.subject}'")
    print(f"  - body: '{result.body[:50]}...' ({len(result.body)} chars)")
    print(f"  - links: {result.links}")
    print(f"  - domains: {result.domains}")
    print(f"  - headers: {dict(list(result.headers.items())[:3])}...")
    print(f"  - timestamp: {result.timestamp}")
    print()
    print("This structured data is what gets passed to Block 2 (Detection)!")


def main():
    """Run all demos."""
    print("🚀 BLOCK 1 DEMONSTRATION - EMAIL PARSER")
    print("This shows exactly what input we work with and what we extract\n")
    
    demo_phishing_email()
    print("\n" + "="*70 + "\n")
    
    demo_plain_text()
    print("\n" + "="*70 + "\n")
    
    demo_legitimate_email()
    print("\n" + "="*70 + "\n")
    
    show_data_structure()
    
    print("🎯 KEY TAKEAWAYS:")
    print("1. We can handle both proper email messages AND plain text")
    print("2. We extract ALL links and domains automatically")
    print("3. We create a clean, structured data object")
    print("4. This structured data feeds into Block 2 (Detection Rules)")
    print("\nBlock 1 is complete and working! Ready for Block 2? 🚀")


if __name__ == "__main__":
    main() 