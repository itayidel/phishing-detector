"""
Advanced Pattern Matching Module - Block 3
Uses sophisticated regex patterns and analysis techniques to detect phishing.
This builds on Block 1 and 2 by adding more advanced detection methods.
"""

import re
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from models import EmailData, DetectionResult


class PatternDetector:
    """
    Advanced pattern-based phishing detector using regex and sophisticated analysis.
    This detector looks for subtle patterns that basic rules might miss.
    """
    
    def __init__(self):
        """Initialize the pattern detector with complex regex patterns and rules."""
        
        # REGEX PATTERN 1: Phone number patterns
        # This catches emails asking for phone numbers (often phishing)
        # Matches formats like: (123) 456-7890, 123-456-7890, 123.456.7890, +1-123-456-7890
        self.phone_patterns = [
            r'\(\d{3}\)\s*\d{3}-\d{4}',           # (123) 456-7890
            r'\d{3}-\d{3}-\d{4}',                 # 123-456-7890
            r'\d{3}\.\d{3}\.\d{4}',               # 123.456.7890
            r'\+\d{1,3}-\d{3}-\d{3}-\d{4}',       # +1-123-456-7890
            r'\d{10}',                            # 1234567890 (10 digits)
        ]
        
        # REGEX PATTERN 2: Social Security Number patterns
        # SSN requests are HUGE red flags - legitimate companies rarely ask for SSN via email
        # Matches formats like: 123-45-6789, 123 45 6789
        self.ssn_patterns = [
            r'\d{3}-\d{2}-\d{4}',                 # 123-45-6789
            r'\d{3}\s\d{2}\s\d{4}',               # 123 45 6789
            r'ssn|social security',               # Any mention of SSN
        ]
        
        # REGEX PATTERN 3: Credit card patterns
        # Credit card requests in emails are almost always phishing
        # Matches common CC formats: 4 groups of 4 digits, spaces or dashes
        self.credit_card_patterns = [
            r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',  # 1234 5678 9012 3456
            r'credit card|card number|cvv|cvc',          # Any CC-related terms
        ]
        
        # REGEX PATTERN 4: Password/credential harvesting patterns
        # These words indicate the email is trying to steal login credentials
        self.credential_patterns = [
            r'password|username|login|sign[\s-]?in',     # Login-related terms
            r'credential|authentication|two[\s-]?factor', # Security terms
            r'pin|passcode|security code',                # PIN/code requests
        ]
        
        # PATTERN 5: URL shortener services (more comprehensive than basic detector)
        # These services hide the real destination, making them perfect for phishing
        self.url_shorteners = {
            # Popular URL shorteners
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'rb.gy',
            
            # Lesser-known but still suspicious shorteners
            'cutt.ly', 'shorte.st', 'bc.vc', 'clicky.me', 'clickme.net',
            'fur.ly', 'go2l.ink', 'hideuri.com', 'liinks.co', 'linkbun.ch',
            'lnkd.in', 'mcaf.ee', 'moourl.com', 'qr.ae', 'qr.net',
            'scrnch.me', 'su.pr', 'tighturl.com', 'tmi.me', 'togoto.us',
            'tr.im', 'tweez.me', 'twurl.cc', 'vzturl.com', 'x.co', 'xrl.us'
        }
        
        # PATTERN 6: Suspicious file extensions in URLs
        # These file types are commonly used to deliver malware
        self.suspicious_extensions = {
            # Executable files - these can run malware
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            
            # Document files that can contain macros
            '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
            
            # Archive files that might contain malware
            '.zip', '.rar', '.7z', '.tar', '.gz'
        }
        
        # PATTERN 7: Lookalike character substitutions
        # Attackers use these to make fake domains look real
        # For example: "paypaI.com" (capital i instead of lowercase L)
        self.lookalike_chars = {
            'o': ['0', 'ο', 'о'],          # o vs zero vs Greek omicron vs Cyrillic o
            'l': ['1', 'I', '|', 'ǀ'],     # l vs one vs capital i vs pipe
            'e': ['3', 'е'],               # e vs three vs Cyrillic e
            'a': ['а', '@'],               # a vs Cyrillic a vs at symbol
            'i': ['1', 'l', '|', 'ǀ'],     # i vs one vs l vs pipe
            'u': ['υ', 'ս'],               # u vs Greek upsilon vs Armenian s
            'p': ['р'],                    # p vs Cyrillic p
            'c': ['с', 'ϲ'],               # c vs Cyrillic c vs Greek c
            'x': ['х', 'χ'],               # x vs Cyrillic x vs Greek chi
            'y': ['у', 'ɣ'],               # y vs Cyrillic y vs Latin gamma
            'h': ['һ', 'Ꮋ'],               # h vs Cyrillic h vs Cherokee H
            'n': ['η', 'ո'],               # n vs Greek eta vs Armenian n
            'm': ['м', 'ṁ'],               # m vs Cyrillic m vs Latin m with dot
            'k': ['κ', 'ĸ'],               # k vs Greek kappa vs Latin k
            'b': ['в', 'ḅ'],               # b vs Cyrillic v vs Latin b with dot
            'g': ['ց', 'ɡ'],               # g vs Armenian g vs Latin g
            'r': ['г', 'ŗ'],               # r vs Cyrillic g vs Latin r
            'd': ['ԁ', 'ď'],               # d vs Cyrillic d vs Latin d
            'f': ['ḟ', 'ẝ'],               # f vs Latin f with dot vs long s
            'v': ['ѵ', 'ʋ'],               # v vs Cyrillic v vs Latin v
            'w': ['ѡ', 'ɯ'],               # w vs Cyrillic omega vs turned m
            'z': ['ᴢ', 'ᶻ'],               # z vs small caps z vs superscript z
            'q': ['ʠ', 'ɋ'],               # q vs Latin q with hook vs small q
            'j': ['ϳ', 'ĵ'],               # j vs Greek j vs Latin j with circumflex
            's': ['ѕ', 'ʂ'],               # s vs Cyrillic s vs Latin s with hook
            't': ['τ', 'ţ'],               # t vs Greek tau vs Latin t with cedilla
        }
        
        # PATTERN 8: Suspicious domain TLDs (top-level domains)
        # Some TLDs are more commonly used for phishing than others
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf',    # Free TLD services
            '.click', '.download', '.zip', '.rar',  # Suspicious new TLDs
            '.security', '.secure', '.bank', '.login'  # Domains pretending to be secure
        }
        
        # PATTERN 9: Suspicious URL parameters
        # These parameters in URLs often indicate phishing attempts
        self.suspicious_url_params = {
            'token', 'verify', 'confirm', 'validate', 'auth', 'login',
            'redirect', 'return', 'continue', 'next', 'url', 'goto',
            'user', 'account', 'id', 'session', 'key', 'code'
        }
        
        # PATTERN 10: Email header spoofing indicators
        # These headers can be forged to make emails look legitimate
        self.spoofing_headers = {
            'return-path', 'reply-to', 'from', 'sender', 'x-originating-ip'
        }
    
    def analyze(self, email_data: EmailData) -> DetectionResult:
        """
        Main analysis function - this is where all the advanced pattern matching happens!
        This function coordinates all the different pattern checks.
        
        Args:
            email_data (EmailData): Parsed email data from Block 1
            
        Returns:
            DetectionResult: Advanced pattern analysis results
        """
        # Start with zero risk - each test will add risk points
        risk_score = 0
        # Keep track of all suspicious patterns we find
        reasons = []
        
        # TEST 1: Look for sensitive information requests (phone, SSN, credit card)
        # Legitimate companies rarely ask for this via email
        sensitive_risk, sensitive_reasons = self._check_sensitive_info_requests(email_data.body)
        risk_score += sensitive_risk  # Add risk points from this test
        reasons.extend(sensitive_reasons)  # Add explanations
        
        # TEST 2: Analyze URLs for advanced suspicious patterns
        # Look for URL shorteners, suspicious file extensions, and malicious parameters
        url_risk, url_reasons = self._check_advanced_url_patterns(email_data.links)
        risk_score += url_risk  # Add risk points
        reasons.extend(url_reasons)  # Add explanations
        
        # TEST 3: Check for sophisticated domain spoofing
        # Look for domains that use lookalike characters to fool people
        domain_risk, domain_reasons = self._check_lookalike_domains(email_data.domains)
        risk_score += domain_risk  # Add risk points
        reasons.extend(domain_reasons)  # Add explanations
        
        # TEST 4: Analyze email headers for spoofing indicators
        # Check if headers have been manipulated to hide the real sender
        header_risk, header_reasons = self._check_header_spoofing(email_data.headers)
        risk_score += header_risk  # Add risk points
        reasons.extend(header_reasons)  # Add explanations
        
        # TEST 5: Look for credential harvesting attempts
        # Check if the email is trying to steal login information
        credential_risk, credential_reasons = self._check_credential_harvesting(email_data.body)
        risk_score += credential_risk  # Add risk points
        reasons.extend(credential_reasons)  # Add explanations
        
        # TEST 6: Check for suspicious TLD usage
        # Some top-level domains are more commonly used for phishing
        tld_risk, tld_reasons = self._check_suspicious_tlds(email_data.domains)
        risk_score += tld_risk  # Add risk points
        reasons.extend(tld_reasons)  # Add explanations
        
        # TEST 7: Advanced URL parameter analysis
        # Look for suspicious parameters that might indicate phishing
        param_risk, param_reasons = self._check_url_parameters(email_data.links)
        risk_score += param_risk  # Add risk points
        reasons.extend(param_reasons)  # Add explanations
        
        # Make sure risk score doesn't exceed 100 (maximum possible)
        risk_score = min(risk_score, 100)
        
        # Determine classification based on risk score
        # The pattern detector tends to be more conservative than basic detector
        if risk_score >= 75:
            classification = "Phishing"      # Very high confidence phishing
            confidence = 0.95               # 95% confident
        elif risk_score >= 45:
            classification = "Suspicious"    # Suspicious patterns found
            confidence = 0.80               # 80% confident
        else:
            classification = "Safe"          # No significant patterns found
            confidence = 0.75               # 75% confident (patterns can be subtle)
        
        # Create and return the final result
        return DetectionResult(
            risk_score=risk_score,           # Total risk score (0-100)
            classification=classification,    # "Safe", "Suspicious", or "Phishing"
            confidence=confidence,           # How confident we are (0.0-1.0)
            reasons=reasons,                 # List of all patterns we found
            module_name="PatternDetector"    # Which detector created this result
        )
    
    def _check_sensitive_info_requests(self, body: str) -> Tuple[int, List[str]]:
        """
        TEST 1: Check for requests for sensitive information.
        Legitimate companies rarely ask for SSN, phone, or credit card info via email.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Track what we find
        
        # Convert body to lowercase for easier pattern matching
        body_lower = body.lower()
        
        # CHECK FOR PHONE NUMBER REQUESTS
        # Look for phone number patterns or requests
        phone_matches = []  # Keep track of phone patterns we find
        for pattern in self.phone_patterns:
            # Use regex to find phone number patterns
            matches = re.findall(pattern, body_lower)
            phone_matches.extend(matches)  # Add any matches to our list
        
        # If we found phone number patterns, it's suspicious
        if phone_matches:
            risk += 25  # Add 25 points - phone requests are suspicious
            reasons.append(f"Phone number patterns detected: {len(phone_matches)} instances")
        
        # CHECK FOR SSN REQUESTS
        # Social Security Number requests are huge red flags
        ssn_matches = []  # Keep track of SSN patterns we find
        for pattern in self.ssn_patterns:
            # Use regex to find SSN patterns
            matches = re.findall(pattern, body_lower)
            ssn_matches.extend(matches)  # Add any matches to our list
        
        # If we found SSN patterns, it's very suspicious
        if ssn_matches:
            risk += 40  # Add 40 points - SSN requests are very suspicious
            reasons.append(f"Social Security Number patterns detected: {len(ssn_matches)} instances")
        
        # CHECK FOR CREDIT CARD REQUESTS
        # Credit card info requests via email are almost always phishing
        cc_matches = []  # Keep track of credit card patterns we find
        for pattern in self.credit_card_patterns:
            # Use regex to find credit card patterns
            matches = re.findall(pattern, body_lower)
            cc_matches.extend(matches)  # Add any matches to our list
        
        # If we found credit card patterns, it's very suspicious
        if cc_matches:
            risk += 35  # Add 35 points - credit card requests are very suspicious
            reasons.append(f"Credit card patterns detected: {len(cc_matches)} instances")
        
        # Return total risk and reasons from this test
        return risk, reasons
    
    def _check_advanced_url_patterns(self, links: List[str]) -> Tuple[int, List[str]]:
        """
        TEST 2: Advanced URL pattern analysis.
        Look for URL shorteners, suspicious file extensions, and other URL tricks.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Track what we find
        
        # Go through each link in the email
        for link in links:
            try:
                # Parse the URL to get its components
                parsed_url = urlparse(link)
                domain = parsed_url.netloc.lower()  # Get the domain part
                path = parsed_url.path.lower()      # Get the path part
                
                # CHECK 1: Is this a URL shortener?
                # URL shorteners hide the real destination
                if domain in self.url_shorteners:
                    risk += 20  # Add 20 points - URL shorteners are suspicious
                    reasons.append(f"URL shortener detected: {domain}")
                
                # CHECK 2: Does the URL end with a suspicious file extension?
                # These files can contain malware
                for extension in self.suspicious_extensions:
                    if path.endswith(extension):
                        risk += 30  # Add 30 points - suspicious files are dangerous
                        reasons.append(f"Suspicious file extension in URL: {extension}")
                        break  # Stop after finding first suspicious extension
                
                # CHECK 3: Is the URL suspiciously long?
                # Long URLs are often used to hide malicious content
                if len(link) > 200:
                    risk += 15  # Add 15 points - very long URLs are suspicious
                    reasons.append(f"Extremely long URL detected: {len(link)} characters")
                
                # CHECK 4: Does the URL contain suspicious keywords?
                # Words like "login", "verify", "secure" in URLs can be tricks
                suspicious_url_keywords = ['login', 'verify', 'secure', 'update', 'confirm']
                for keyword in suspicious_url_keywords:
                    if keyword in link.lower():
                        risk += 10  # Add 10 points - suspicious keywords
                        reasons.append(f"Suspicious keyword in URL: {keyword}")
                        break  # Stop after finding first keyword
                
            except Exception as e:
                # If we can't parse the URL, it's probably malformed
                risk += 15  # Add 15 points - malformed URLs are suspicious
                reasons.append(f"Malformed URL detected: {link[:50]}...")
        
        # Return total risk and reasons from this test
        return risk, reasons
    
    def _check_lookalike_domains(self, domains: List[str]) -> Tuple[int, List[str]]:
        """
        TEST 3: Check for sophisticated domain spoofing using lookalike characters.
        Attackers use characters that look similar to fool people (like 'o' vs '0').
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Track what we find
        
        # List of popular services that are commonly spoofed
        popular_services = [
            'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
            'netflix', 'ebay', 'instagram', 'twitter', 'linkedin', 'youtube',
            'banking', 'bank', 'credit', 'secure', 'login', 'account'
        ]
        
        # Go through each domain found in the email
        for domain in domains:
            domain_lower = domain.lower()  # Convert to lowercase for comparison
            
            # Check if this domain looks like a popular service
            for service in popular_services:
                # If the domain contains the service name but isn't the real domain
                if service in domain_lower and not domain_lower.endswith(f'{service}.com'):
                    
                    # CHECK FOR LOOKALIKE CHARACTER SUBSTITUTION
                    # See if the domain uses lookalike characters
                    if self._has_lookalike_chars(domain_lower, service):
                        risk += 35  # Add 35 points - lookalike domains are very suspicious
                        reasons.append(f"Lookalike domain with character substitution: {domain}")
                        break  # Stop after finding first lookalike
                    
                    # CHECK FOR SUBDOMAIN SPOOFING
                    # Like "paypal.malicious-site.com" instead of "paypal.com"
                    elif f'{service}.' in domain_lower:
                        risk += 30  # Add 30 points - subdomain spoofing
                        reasons.append(f"Potential subdomain spoofing: {domain}")
                        break  # Stop after finding first spoofing attempt
                    
                    # CHECK FOR PREFIX/SUFFIX SPOOFING
                    # Like "secure-paypal.com" or "paypal-security.com"
                    elif service in domain_lower:
                        risk += 25  # Add 25 points - prefix/suffix spoofing
                        reasons.append(f"Potential service name spoofing: {domain}")
                        break  # Stop after finding first spoofing attempt
        
        # Return total risk and reasons from this test
        return risk, reasons
    
    def _has_lookalike_chars(self, domain: str, service: str) -> bool:
        """
        Helper function to check if a domain uses lookalike characters.
        Compares the domain with the service name to find character substitutions.
        """
        # Go through each character in the service name
        for i, char in enumerate(service):
            # If this character has known lookalikes
            if char in self.lookalike_chars:
                # Check if the domain uses any of the lookalike characters
                for lookalike in self.lookalike_chars[char]:
                    if lookalike in domain:
                        return True  # Found a lookalike character substitution
        
        return False  # No lookalike characters found
    
    def _check_header_spoofing(self, headers: Dict[str, str]) -> Tuple[int, List[str]]:
        """
        TEST 4: Check email headers for spoofing indicators.
        Email headers can be forged to make emails look legitimate.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Track what we find
        
        # If we don't have headers, we can't check for spoofing
        if not headers:
            return risk, reasons
        
        # Convert all header names to lowercase for easier checking
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # CHECK 1: Compare 'From' and 'Return-Path' headers
        # These should typically match for legitimate emails
        if 'from' in headers_lower and 'return-path' in headers_lower:
            from_header = headers_lower['from']
            return_path = headers_lower['return-path']
            
            # Extract email addresses from both headers
            from_email = self._extract_email_from_header(from_header)
            return_email = self._extract_email_from_header(return_path)
            
            # If the domains don't match, it might be spoofing
            if from_email and return_email:
                from_domain = from_email.split('@')[1] if '@' in from_email else ''
                return_domain = return_email.split('@')[1] if '@' in return_email else ''
                
                if from_domain != return_domain:
                    risk += 20  # Add 20 points - header mismatch
                    reasons.append(f"Header mismatch: From domain ({from_domain}) != Return-Path domain ({return_domain})")
        
        # CHECK 2: Look for multiple 'Received' headers with suspicious patterns
        # Legitimate emails typically have a clear path through mail servers
        received_headers = [v for k, v in headers_lower.items() if k.startswith('received')]
        if len(received_headers) > 10:
            risk += 15  # Add 15 points - too many received headers
            reasons.append(f"Excessive Received headers: {len(received_headers)} found")
        
        # CHECK 3: Check for missing important headers
        # Legitimate emails usually have these headers
        important_headers = ['message-id', 'date', 'from']
        missing_headers = [header for header in important_headers if header not in headers_lower]
        
        if missing_headers:
            risk += 10  # Add 10 points - missing headers
            reasons.append(f"Missing important headers: {', '.join(missing_headers)}")
        
        # CHECK 4: Look for suspicious X-Originating-IP patterns
        # This header can reveal the real source of the email
        if 'x-originating-ip' in headers_lower:
            originating_ip = headers_lower['x-originating-ip']
            # Check if IP looks suspicious (this is a simplified check)
            if self._is_suspicious_ip(originating_ip):
                risk += 15  # Add 15 points - suspicious originating IP
                reasons.append(f"Suspicious originating IP: {originating_ip}")
        
        # Return total risk and reasons from this test
        return risk, reasons
    
    def _extract_email_from_header(self, header_value: str) -> Optional[str]:
        """
        Helper function to extract email address from a header value.
        Headers can have formats like "Name <email@domain.com>" or just "email@domain.com".
        """
        # Use regex to find email addresses in the header
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        matches = re.findall(email_pattern, header_value)
        
        # Return the first email found, or None if no email found
        return matches[0] if matches else None
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """
        Helper function to check if an IP address looks suspicious.
        This is a simplified check - in practice, you'd use threat intelligence feeds.
        """
        # Check for private IP ranges (these shouldn't be originating IPs for external emails)
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
        ]
        
        # If the IP starts with a private range, it's suspicious for external email
        for private_range in private_ranges:
            if ip_address.startswith(private_range):
                return True
        
        return False  # IP doesn't look suspicious
    
    def _check_credential_harvesting(self, body: str) -> Tuple[int, List[str]]:
        """
        TEST 5: Check for credential harvesting attempts.
        Look for patterns that indicate the email is trying to steal login information.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Track what we find
        
        # Convert body to lowercase for easier pattern matching
        body_lower = body.lower()
        
        # CHECK FOR CREDENTIAL-RELATED PATTERNS
        # Look for words that indicate credential harvesting
        credential_matches = []  # Keep track of credential patterns we find
        for pattern in self.credential_patterns:
            # Use regex to find credential patterns
            matches = re.findall(pattern, body_lower)
            credential_matches.extend(matches)  # Add any matches to our list
        
        # The more credential-related terms, the more suspicious
        if len(credential_matches) >= 3:
            risk += 30  # Add 30 points - high credential focus
            reasons.append(f"High credential harvesting indicators: {len(credential_matches)} instances")
        elif len(credential_matches) >= 1:
            risk += 15  # Add 15 points - some credential focus
            reasons.append(f"Credential harvesting indicators detected: {len(credential_matches)} instances")
        
        # CHECK FOR SPECIFIC CREDENTIAL HARVESTING PHRASES
        # These phrases are commonly used in credential harvesting emails
        harvesting_phrases = [
            'verify your password', 'confirm your login', 'update your credentials',
            'your account has been locked', 'suspicious login attempt',
            'verify your identity', 'confirm your account', 'update payment information'
        ]
        
        # Look for these specific phrases
        for phrase in harvesting_phrases:
            if phrase in body_lower:
                risk += 20  # Add 20 points - specific harvesting phrase
                reasons.append(f"Credential harvesting phrase detected: '{phrase}'")
                break  # Stop after finding first phrase
        
        # Return total risk and reasons from this test
        return risk, reasons
    
    def _check_suspicious_tlds(self, domains: List[str]) -> Tuple[int, List[str]]:
        """
        TEST 6: Check for suspicious top-level domains (TLDs).
        Some TLDs are more commonly used for phishing than others.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Track what we find
        
        # Go through each domain found in the email
        for domain in domains:
            domain_lower = domain.lower()  # Convert to lowercase for comparison
            
            # Check if the domain ends with a suspicious TLD
            for tld in self.suspicious_tlds:
                if domain_lower.endswith(tld):
                    risk += 15  # Add 15 points - suspicious TLD
                    reasons.append(f"Suspicious TLD detected: {domain} (uses {tld})")
                    break  # Stop after finding first suspicious TLD
        
        # Return total risk and reasons from this test
        return risk, reasons
    
    def _check_url_parameters(self, links: List[str]) -> Tuple[int, List[str]]:
        """
        TEST 7: Check URL parameters for suspicious patterns.
        Phishing URLs often have suspicious parameters like 'token' or 'verify'.
        """
        risk = 0  # Start with zero risk for this test
        reasons = []  # Track what we find
        
        # Go through each link in the email
        for link in links:
            try:
                # Parse the URL to get its components
                parsed_url = urlparse(link)
                
                # Get the query parameters (the part after '?' in the URL)
                query_params = parse_qs(parsed_url.query)
                
                # Check each parameter name
                for param_name in query_params.keys():
                    param_name_lower = param_name.lower()
                    
                    # If this parameter name is suspicious
                    if param_name_lower in self.suspicious_url_params:
                        risk += 10  # Add 10 points - suspicious parameter
                        reasons.append(f"Suspicious URL parameter: {param_name} in {link[:50]}...")
                        break  # Stop after finding first suspicious parameter in this URL
                
                # CHECK FOR TOO MANY PARAMETERS
                # URLs with lots of parameters can be suspicious
                if len(query_params) > 10:
                    risk += 10  # Add 10 points - too many parameters
                    reasons.append(f"URL with excessive parameters: {len(query_params)} parameters")
                
            except Exception:
                # If we can't parse the URL, skip it
                continue
        
        # Return total risk and reasons from this test
        return risk, reasons


# Convenience function for quick pattern detection
def detect_patterns(email_data: EmailData) -> DetectionResult:
    """
    Quick function to detect patterns without creating a detector instance.
    
    Args:
        email_data (EmailData): Parsed email data
        
    Returns:
        DetectionResult: Pattern detection result with risk score and explanations
    """
    detector = PatternDetector()
    return detector.analyze(email_data)


if __name__ == "__main__":
    # Simple test when running this file directly
    from email_parser import parse_email
    
    # Test with a sophisticated phishing email
    test_email = """From: security@paypaI.com
Subject: Verify Your Account - Action Required
Return-Path: noreply@suspicious-domain.tk

Dear Customer,

We detected suspicious activity on your account. Please verify your login credentials immediately.

Click here to verify: https://paypal-verify.tk/login?token=abc123&verify=true&user=victim

You must provide your:
- Username and password
- Social Security Number: 123-45-6789
- Credit card number
- Phone number: (555) 123-4567

If you don't verify within 24 hours, your account will be suspended.

Security Team
PayPal (Not really PayPal)
"""
    
    # Parse and analyze with pattern detector
    email_data = parse_email(test_email)
    result = detect_patterns(email_data)
    
    print("=== Pattern Detector Test ===")
    print(f"Risk Score: {result.risk_score}/100")
    print(f"Classification: {result.classification}")
    print(f"Confidence: {result.confidence:.2f}")
    print("Patterns Found:")
    for reason in result.reasons:
        print(f"  - {reason}") 