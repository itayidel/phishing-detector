"""
Test file for EmailParser - Block 1 validation
Tests various email formats and parsing scenarios.
"""

from email_parser import EmailParser, parse_email
from models import EmailData


def test_full_email_message():
    """Test parsing a complete email message with headers."""
    sample_email = """From: sender@example.com
To: recipient@company.com
Subject: Test Email
Date: Wed, 01 Jan 2024 12:00:00 +0000

This is a test email with a link: https://example.com/page
And another link: http://suspicious-site.com/verify
"""
    
    result = parse_email(sample_email)
    
    print("=== Test 1: Full Email Message ===")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Links: {result.links}")
    print(f"Domains: {result.domains}")
    print(f"Headers count: {len(result.headers)}")
    print(f"Timestamp: {result.timestamp}")
    print()
    
    # Basic assertions
    assert result.sender == "sender@example.com"
    assert result.subject == "Test Email"
    assert len(result.links) == 2
    assert "example.com" in result.domains
    assert "suspicious-site.com" in result.domains
    print("✓ Full email message test passed")


def test_plain_text_content():
    """Test parsing plain text content without proper headers."""
    plain_text = """Urgent: Account Verification Required
    
Please verify your account by clicking: https://phishing-site.com/verify
    
This is urgent and requires immediate action.
Call us at 1-800-SCAM-NOW
"""
    
    result = parse_email(plain_text)
    
    print("=== Test 2: Plain Text Content ===")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Links: {result.links}")
    print(f"Domains: {result.domains}")
    print()
    
    assert len(result.links) == 1
    assert "phishing-site.com" in result.domains
    assert result.subject == "Urgent: Account Verification Required"
    print("✓ Plain text content test passed")


def test_multiple_links():
    """Test extraction of multiple URLs from email content."""
    email_with_links = """From: newsletter@company.com
Subject: Weekly Updates

Check out these links:
- Main site: https://company.com
- Support: https://support.company.com/help
- Social: https://facebook.com/company
- Suspicious: http://bit.ly/fakepage
"""
    
    result = parse_email(email_with_links)
    
    print("=== Test 3: Multiple Links ===")
    print(f"Links found: {len(result.links)}")
    print(f"Links: {result.links}")
    print(f"Domains: {result.domains}")
    print()
    
    assert len(result.links) == 4
    assert "company.com" in result.domains
    assert "bit.ly" in result.domains
    print("✓ Multiple links test passed")


def test_no_links():
    """Test email with no links."""
    no_links_email = """From: friend@example.com
Subject: Just saying hi

Hey there!

Just wanted to say hello and see how you're doing.
No links here, just a friendly message.

Best regards,
Your friend
"""
    
    result = parse_email(no_links_email)
    
    print("=== Test 4: No Links ===")
    print(f"Links found: {len(result.links)}")
    print(f"Domains: {result.domains}")
    print()
    
    assert len(result.links) == 0
    assert len(result.domains) == 0
    print("✓ No links test passed")


def test_malformed_email():
    """Test handling of malformed or incomplete email content."""
    malformed = "This is not really an email but should be parsed somehow"
    
    result = parse_email(malformed)
    
    print("=== Test 5: Malformed Email ===")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Body length: {len(result.body)}")
    print()
    
    assert result.sender == "unknown@unknown.com"
    assert result.subject == "This is not really an email but should be parsed somehow"
    assert result.body == malformed
    print("✓ Malformed email test passed")


def test_email_with_from_in_body():
    """Test email where 'From:' appears in the body, not header."""
    tricky_email = """Subject: Meeting Update

From: John, I wanted to let you know about the meeting.
The agenda is available at https://docs.company.com/agenda

Please confirm your attendance.
"""
    
    result = parse_email(tricky_email)
    
    print("=== Test 6: From in Body ===")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Links: {result.links}")
    print()
    
    assert result.subject == "Meeting Update"
    assert len(result.links) == 1
    print("✓ From in body test passed")


def run_all_tests():
    """Run all email parser tests."""
    print("Starting Email Parser Tests...\n")
    
    try:
        test_full_email_message()
        test_plain_text_content()
        test_multiple_links()
        test_no_links()
        test_malformed_email()
        test_email_with_from_in_body()
        
        print("\n🎉 All tests passed! Email Parser is working correctly.")
        print("\nBlock 1 (Email Parser) is complete and ready for Block 2!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        print("Please check the implementation.")


if __name__ == "__main__":
    run_all_tests() 