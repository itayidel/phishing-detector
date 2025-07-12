"""
Email Parser Module - Block 1
Extracts structured data from raw email content.
This is the foundation module that all other detection blocks depend on.
"""

import re
import email
from email.message import Message
from typing import List, Dict, Optional
from urllib.parse import urlparse
from datetime import datetime
from models import EmailData


class EmailParser:
    """
    Parses raw email content into structured EmailData objects.
    Handles both string content and email.message.EmailMessage objects.
    """
    
    def __init__(self):
        """Initialize the email parser with common patterns."""
        # Common URL patterns to catch various link formats
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        # Pattern to find email addresses
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    def parse(self, raw_email: str) -> EmailData:
        """
        Parse raw email content into structured EmailData.
        
        Args:
            raw_email (str): Raw email content (can be email headers + body or just body)
            
        Returns:
            EmailData: Structured email data ready for analysis
        """
        try:
            # Try to parse as a proper email message first
            if self._looks_like_email_message(raw_email):
                email_msg = email.message_from_string(raw_email)
                return self._parse_email_message(email_msg)
            else:
                # Parse as plain text content
                return self._parse_plain_text(raw_email)
                
        except Exception as e:
            # If parsing fails, create a basic EmailData with what we can extract
            return self._create_fallback_email_data(raw_email, str(e))
    
    def _looks_like_email_message(self, content: str) -> bool:
        """Check if content looks like a proper email message with headers."""
        # Look for common email headers
        header_patterns = [
            r'^From:', r'^To:', r'^Subject:', r'^Date:', r'^Message-ID:'
        ]
        
        for pattern in header_patterns:
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                return True
        return False
    
    def _parse_email_message(self, email_msg: Message) -> EmailData:
        """Parse a proper email.message.Message object."""
        # Extract basic fields
        sender = email_msg.get('From', 'unknown@unknown.com')
        subject = email_msg.get('Subject', 'No Subject')
        
        # Get email body
        body = self._extract_body(email_msg)
        
        # Extract all headers
        headers = dict(email_msg.items())
        
        # Parse timestamp
        timestamp = self._parse_timestamp(email_msg.get('Date'))
        
        # Extract links and domains
        links = self._extract_links(body)
        domains = self._extract_domains(links)
        
        return EmailData(
            sender=sender,
            subject=subject,
            body=body,
            links=links,
            domains=domains,
            headers=headers,
            timestamp=timestamp
        )
    
    def _parse_plain_text(self, content: str) -> EmailData:
        """Parse plain text content (no proper email headers)."""
        # Try to extract sender from content if possible
        sender = self._extract_sender_from_text(content)
        
        # Use first line as subject if it looks like one
        subject = self._extract_subject_from_text(content)
        
        # Extract links and domains
        links = self._extract_links(content)
        domains = self._extract_domains(links)
        
        return EmailData(
            sender=sender,
            subject=subject,
            body=content,
            links=links,
            domains=domains,
            headers={},
            timestamp=None
        )
    
    def _extract_body(self, email_msg: Message) -> str:
        """Extract the body content from an email message."""
        if email_msg.is_multipart():
            body_parts = []
            for part in email_msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        body_parts.append(payload.decode('utf-8', errors='ignore'))
                    else:
                        body_parts.append(str(payload))
                elif part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        body_parts.append(payload.decode('utf-8', errors='ignore'))
                    else:
                        body_parts.append(str(payload))
            return '\n'.join(body_parts)
        else:
            payload = email_msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload.decode('utf-8', errors='ignore')
            else:
                return str(payload)
    
    def _extract_links(self, text: str) -> List[str]:
        """Extract all URLs from text content."""
        links = self.url_pattern.findall(text)
        # Remove duplicates and validate
        unique_links = []
        for link in links:
            if link not in unique_links and self._is_valid_url(link):
                unique_links.append(link)
        return unique_links
    
    def _is_valid_url(self, url: str) -> bool:
        """Simple URL validation."""
        try:
            parsed = urlparse(url)
            return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
        except Exception:
            return False
    
    def _extract_domains(self, links: List[str]) -> List[str]:
        """Extract domain names from a list of URLs."""
        domains = []
        for link in links:
            try:
                parsed = urlparse(link)
                if parsed.netloc and parsed.netloc not in domains:
                    domains.append(parsed.netloc)
            except Exception:
                continue
        return domains
    
    def _extract_sender_from_text(self, text: str) -> str:
        """Try to extract sender email from plain text."""
        # Look for common patterns like "From: email@domain.com"
        from_match = re.search(r'From:\s*([^\s\n]+@[^\s\n]+)', text, re.IGNORECASE)
        if from_match:
            return from_match.group(1)
        
        # Look for any email address in the first few lines
        lines = text.split('\n')[:5]
        for line in lines:
            emails = self.email_pattern.findall(line)
            if emails:
                return emails[0]
        
        return 'unknown@unknown.com'
    
    def _extract_subject_from_text(self, text: str) -> str:
        """Try to extract subject from plain text."""
        # Look for "Subject:" pattern
        subject_match = re.search(r'Subject:\s*([^\n]+)', text, re.IGNORECASE)
        if subject_match:
            return subject_match.group(1).strip()
        
        # Use first line if it's reasonably short
        first_line = text.split('\n')[0].strip()
        if first_line and len(first_line) < 100:
            return first_line
        
        return 'No Subject'
    
    def _parse_timestamp(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse email date string to datetime object."""
        if not date_str:
            return None
        
        try:
            # Try common email date formats
            import email.utils
            parsed_date = email.utils.parsedate_tz(date_str)
            if parsed_date:
                return datetime.fromtimestamp(email.utils.mktime_tz(parsed_date))
            return None
        except Exception:
            return None
    
    def _create_fallback_email_data(self, raw_content: str, error: str) -> EmailData:
        """Create basic EmailData when parsing fails."""
        return EmailData(
            sender='parsing_failed@unknown.com',
            subject=f'Parsing Error: {error[:50]}...',
            body=raw_content,
            links=[],
            domains=[],
            headers={},
            timestamp=None
        )


# Convenience function for quick parsing
def parse_email(raw_email: str) -> EmailData:
    """
    Quick function to parse an email without creating a parser instance.
    
    Args:
        raw_email (str): Raw email content
        
    Returns:
        EmailData: Parsed email data
    """
    parser = EmailParser()
    return parser.parse(raw_email)


if __name__ == "__main__":
    # Simple test when running this file directly
    sample_email = """From: suspicious@phishing-site.com
To: victim@company.com
Subject: URGENT: Verify your account immediately!

Dear valued customer,

Your account has been suspended due to suspicious activity. 
Please click the link below to verify your account immediately:

https://secure-bank-verification.malicious-site.com/verify?token=abc123

If you don't verify within 24 hours, your account will be permanently closed.

Thank you,
Customer Service Team
"""
    
    result = parse_email(sample_email)
    print("=== Email Parser Test ===")
    print(f"Sender: {result.sender}")
    print(f"Subject: {result.subject}")
    print(f"Links found: {len(result.links)}")
    print(f"Domains: {result.domains}")
    print(f"Body preview: {result.body[:100]}...") 