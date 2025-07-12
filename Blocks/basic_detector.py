"""
Basic Rule-Based Detection - Block 2
Implements simple but effective heuristics to detect phishing emails.
Uses common patterns and suspicious indicators.
"""

import re
from typing import List, Set
from urllib.parse import urlparse
from models import EmailData, DetectionResult


class BasicDetector:
    """
    Basic rule-based phishing detector using heuristics.
    Checks for common phishing indicators and assigns risk scores.
    """
    
    def __init__(self):
        """Initialize the detector with predefined rules and patterns."""
        
        # Create a set of suspicious domains that are commonly used in phishing
        # URL shorteners are suspicious because they hide the real destination
        self.suspicious_domains = {
            # Known URL shortening services - these hide the real destination
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'rb.gy',
            
            # Common phishing domain patterns - attackers often use these prefixes
            # to make domains look official (like "secure-paypal.com")
            'secure-', 'verify-', 'update-', 'confirm-', 'account-',
            'login-', 'banking-', 'paypal-', 'amazon-', 'microsoft-',
            'google-', 'facebook-', 'apple-', 'netflix-'
        }
        
        # Words and phrases that create urgency - phishers use these to pressure victims
        # These words make people panic and act without thinking
        self.urgent_keywords = {
            # Direct urgency words
            'urgent', 'immediate', 'action required', 'verify now', 'click here',
            'confirm immediately', 'suspended', 'locked', 'expires', 'deadline',
            
            # Time pressure phrases
            'limited time', 'act now', 'verify account', 'update payment',
            'confirm identity', 'security alert', 'unusual activity', 'compromised',
            
            # Threatening language
            'unauthorized access', 'temporary hold', 'reactivate', 'validate',
            'prevent closure', 'avoid suspension', 'immediately', 'within 24 hours',
            'final notice', 'last chance', 'expire soon', 'takes effect'
        }
        
        # Known legitimate email domains - these are generally trustworthy
        # We use this to validate if senders are from real services
        self.legitimate_domains = {
            'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
            'company.com', 'organization.org', 'government.gov', 'edu.edu'
        }
        
        # Generic greetings that mass phishing emails use
        # Real companies usually personalize emails with your actual name
        self.generic_greetings = {
            'dear customer', 'dear user', 'dear member', 'dear client',
            'dear account holder', 'dear valued customer', 'hello user',
            'greetings', 'attention', 'dear sir/madam'
        }
    
    def analyze(self, email_data: EmailData) -> DetectionResult:
        """
        Main analysis function - this is where all the magic happens!
        Takes parsed email data and returns a risk assessment.
        
        Args:
            email_data (EmailData): Parsed email data from Block 1
            
        Returns:
            DetectionResult: Risk score and explanation
        """
        # Start with zero risk - innocent until proven guilty
        risk_score = 0
        # Keep track of all the reasons why this email might be suspicious
        reasons = []
        
        # TEST 1: Check if any domains in the email are suspicious
        # This catches URL shorteners and fake domains
        domain_risk, domain_reasons = self._check_suspicious_domains(email_data.domains)
        risk_score += domain_risk  # Add the risk points from this test
        reasons.extend(domain_reasons)  # Add the explanations
        
        # TEST 2: Check if the language creates urgency or pressure
        # Phishers use urgent language to make people panic and click
        language_risk, language_reasons = self._check_urgent_language(email_data.subject, email_data.body)
        risk_score += language_risk  # Add more risk points
        reasons.extend(language_reasons)  # Add more explanations
        
        # TEST 3: Check if the sender looks legitimate
        # Compare sender domain with link domains to catch spoofing
        sender_risk, sender_reasons = self._check_sender_legitimacy(email_data.sender, email_data.domains)
        risk_score += sender_risk  # Keep adding risk points
        reasons.extend(sender_reasons)  # Keep adding explanations
        
        # TEST 4: Check for generic greetings (mass phishing indicator)
        # Real companies usually use your actual name
        greeting_risk, greeting_reasons = self._check_generic_greetings(email_data.body)
        risk_score += greeting_risk  # More risk points
        reasons.extend(greeting_reasons)  # More explanations
        
        # TEST 5: Check for suspicious patterns in URLs
        # Look for IP addresses, long URLs, suspicious keywords
        url_risk, url_reasons = self._check_suspicious_urls(email_data.links)
        risk_score += url_risk  # Even more risk points
        reasons.extend(url_reasons)  # Even more explanations
        
        # TEST 6: Check if there are too many links (spam indicator)
        # Legitimate emails usually don't have tons of links
        link_risk, link_reasons = self._check_link_density(email_data.links, email_data.body)
        risk_score += link_risk  # Final risk points
        reasons.extend(link_reasons)  # Final explanations
        
        # Make sure risk score doesn't go above 100 (maximum risk)
        risk_score = min(risk_score, 100)
        
        # Now decide what this risk score means:
        # HIGH RISK (70-100): Definitely phishing
        if risk_score >= 70:
            classification = "Phishing"
            confidence = 0.9  # We're 90% confident this is phishing
        # MEDIUM RISK (40-69): Suspicious, needs attention
        elif risk_score >= 40:
            classification = "Suspicious"
            confidence = 0.7  # We're 70% confident this is suspicious
        # LOW RISK (0-39): Probably safe
        else:
            classification = "Safe"
            confidence = 0.8  # We're 80% confident this is safe
        
        # Create and return the final result with all our findings
        return DetectionResult(
            risk_score=risk_score,           # Total risk score (0-100)
            classification=classification,    # "Safe", "Suspicious", or "Phishing"
            confidence=confidence,           # How confident we are (0.0-1.0)
            reasons=reasons,                 # List of all the reasons we found
            module_name="BasicDetector"      # Which detector created this result
        )
    
    def _check_suspicious_domains(self, domains: List[str]) -> tuple[int, List[str]]:
        """
        TEST 1: Check if any domains in the email are suspicious.
        This is one of the most important tests because malicious links are the main weapon.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Keep track of what we find
        
        # Go through each domain found in the email
        for domain in domains:
            # RULE 1: Check if domain is in our known suspicious list
            # This catches URL shorteners and known bad domains
            if domain in self.suspicious_domains:
                risk += 30  # Add 30 points - this is serious!
                reasons.append(f"Suspicious domain detected: {domain}")
            
            # RULE 2: Check for suspicious patterns in domain names
            # Look for patterns like "secure-paypal.com" or "verify-amazon.com"
            for pattern in self.suspicious_domains:
                # Only check patterns that end with '-' (like "secure-", "verify-")
                if pattern in domain and pattern.endswith('-'):
                    risk += 25  # Add 25 points - suspicious pattern found
                    reasons.append(f"Domain contains suspicious pattern: {domain}")
                    break  # Stop after finding first pattern (don't double-count)
            
            # RULE 3: Check if domain tries to look like a famous service
            # Like "paypal-security.com" instead of "paypal.com"
            if self._is_lookalike_domain(domain):
                risk += 35  # Add 35 points - this is very suspicious!
                reasons.append(f"Potential lookalike domain: {domain}")
        
        # Return the total risk points and all the reasons we found
        return risk, reasons
    
    def _check_urgent_language(self, subject: str, body: str) -> tuple[int, List[str]]:
        """
        TEST 2: Check for urgent or threatening language.
        Phishers use urgent words to make people panic and click without thinking.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Keep track of what we find
        
        # Combine subject and body into one text and make it lowercase
        # This makes it easier to search for keywords
        text = f"{subject} {body}".lower()
        
        # Look for urgent keywords in the text
        urgent_words_found = []  # Keep track of which urgent words we find
        for keyword in self.urgent_keywords:
            # Check if this urgent keyword appears in the email text
            if keyword in text:
                urgent_words_found.append(keyword)  # Add it to our list
        
        # The more urgent words, the more suspicious the email
        # RULE 1: If we find 3 or more urgent words, it's very suspicious
        if len(urgent_words_found) >= 3:
            risk += 30  # Add 30 points - this is high pressure tactics
            reasons.append(f"High use of urgent language: {', '.join(urgent_words_found[:3])}")
        # RULE 2: If we find 1-2 urgent words, it's somewhat suspicious
        elif len(urgent_words_found) >= 1:
            risk += 15  # Add 15 points - some urgency detected
            reasons.append(f"Urgent language detected: {', '.join(urgent_words_found[:2])}")
        
        # RULE 3: Check for ALL CAPS in the subject (like "URGENT!!!")
        # Count how many characters are uppercase vs total characters
        caps_ratio = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)
        # If more than 50% of the subject is uppercase AND it's longer than 10 chars
        if caps_ratio > 0.5 and len(subject) > 10:
            risk += 15  # Add 15 points - excessive capitalization is suspicious
            reasons.append("Subject uses excessive capitalization")
        
        # Return the total risk points and all the reasons we found
        return risk, reasons
    
    def _check_sender_legitimacy(self, sender: str, domains: List[str]) -> tuple[int, List[str]]:
        """Check if sender appears legitimate."""
        risk = 0
        reasons = []
        
        # Extract sender domain
        if '@' in sender:
            sender_domain = sender.split('@')[1].lower()
            
            # Check if sender domain matches link domains (spoofing attempt)
            for domain in domains:
                if sender_domain != domain and self._are_similar_domains(sender_domain, domain):
                    risk += 25
                    reasons.append(f"Sender domain mismatch: {sender_domain} vs {domain}")
            
            # Check for suspicious sender patterns
            if any(pattern in sender_domain for pattern in ['secure-', 'verify-', 'noreply', 'no-reply']):
                risk += 10
                reasons.append(f"Suspicious sender domain pattern: {sender_domain}")
        
        # Check for generic/fake sender addresses
        if sender in ['admin@', 'support@', 'security@', 'noreply@'] or sender.startswith('no-reply'):
            risk += 10
            reasons.append("Generic sender address detected")
        
        return risk, reasons
    
    def _check_generic_greetings(self, body: str) -> tuple[int, List[str]]:
        """Check for generic greetings that indicate mass phishing."""
        risk = 0
        reasons = []
        
        body_lower = body.lower()
        
        for greeting in self.generic_greetings:
            if greeting in body_lower:
                risk += 10
                reasons.append(f"Generic greeting detected: '{greeting}'")
                break  # Only count one generic greeting
        
        return risk, reasons
    
    def _check_suspicious_urls(self, links: List[str]) -> tuple[int, List[str]]:
        """Check for suspicious URL patterns."""
        risk = 0
        reasons = []
        
        for link in links:
            try:
                parsed = urlparse(link)
                
                # Check for IP addresses instead of domains
                if self._is_ip_address(parsed.netloc):
                    risk += 30
                    reasons.append(f"Link uses IP address: {link}")
                
                # Check for suspicious URL patterns
                if any(pattern in link.lower() for pattern in ['login', 'verify', 'secure', 'update']):
                    risk += 10
                    reasons.append(f"URL contains suspicious keywords: {link}")
                
                # Check for very long URLs (obfuscation)
                if len(link) > 150:
                    risk += 15
                    reasons.append(f"Unusually long URL detected: {link[:50]}...")
                
            except Exception:
                risk += 5
                reasons.append(f"Malformed URL detected: {link}")
        
        return risk, reasons
    
    def _check_link_density(self, links: List[str], body: str) -> tuple[int, List[str]]:
        """Check if there are too many links (spam indicator)."""
        risk = 0
        reasons = []
        
        if len(links) > 5:
            risk += 15
            reasons.append(f"High number of links: {len(links)} links found")
        
        # Check link-to-text ratio
        if len(body) > 0:
            link_ratio = len(' '.join(links)) / len(body)
            if link_ratio > 0.3:  # More than 30% links
                risk += 10
                reasons.append("High link-to-text ratio")
        
        return risk, reasons
    
    def _is_lookalike_domain(self, domain: str) -> bool:
        """Check if domain looks like a well-known service."""
        # Simple heuristic for lookalike domains
        known_services = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix']
        
        for service in known_services:
            if service in domain.lower() and not domain.endswith(f'{service}.com'):
                return True
        
        return False
    
    def _are_similar_domains(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are suspiciously similar."""
        # Simple similarity check
        if abs(len(domain1) - len(domain2)) > 5:
            return False
        
        # Check for common substitutions
        similar_chars = {'0': 'o', '1': 'l', '3': 'e', '5': 's'}
        
        for char, replacement in similar_chars.items():
            if domain1.replace(char, replacement) == domain2 or domain2.replace(char, replacement) == domain1:
                return True
        
        return False
    
    def _is_ip_address(self, address: str) -> bool:
        """Check if address is an IP address."""
        try:
            parts = address.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False


# Convenience function for quick detection
def detect_phishing(email_data: EmailData) -> DetectionResult:
    """
    Quick function to detect phishing without creating a detector instance.
    
    Args:
        email_data (EmailData): Parsed email data
        
    Returns:
        DetectionResult: Detection result with risk score and explanations
    """
    detector = BasicDetector()
    return detector.analyze(email_data)


if __name__ == "__main__":
    # Simple test when running this file directly
    from email_parser import parse_email
    
    # Test with a suspicious email
    test_email = """From: security@paypal-verification.com
Subject: URGENT: Account suspended - verify now!

Dear customer,

Your account has been suspended due to unusual activity.
Click here immediately to verify: https://paypal-secure.suspicious-domain.com/verify

You must act within 24 hours or your account will be permanently closed.

PayPal Security Team
"""
    
    # Parse and analyze
    email_data = parse_email(test_email)
    result = detect_phishing(email_data)
    
    print("=== Basic Detector Test ===")
    print(f"Risk Score: {result.risk_score}/100")
    print(f"Classification: {result.classification}")
    print(f"Confidence: {result.confidence:.2f}")
    print("Reasons:")
    for reason in result.reasons:
        print(f"  - {reason}") 