"""
Data Models - Shared Data Structures
These are the data structures that all detection modules use to communicate.
Think of these as the "common language" between all our detection blocks.
"""

# IMPORT SECTION - Getting the tools we need for data structures
from dataclasses import dataclass  # For creating clean data structures
from typing import List, Dict, Optional  # For type hints (makes code clearer)
from datetime import datetime  # For handling timestamps

# EMAIL DATA STRUCTURE
# This is the standardized format that Block 1 (EmailParser) outputs
# All other detection modules receive this as input
@dataclass
class EmailData:
    """
    Structured representation of an email after parsing.
    
    This is what Block 1 (EmailParser) creates from raw email content.
    All detection modules (Block 2, 3, etc.) receive this as input.
    
    Think of this as a clean, organized version of a messy email.
    """
    
    # BASIC EMAIL FIELDS
    sender: str              # Who sent the email (like "phisher@suspicious.com")
    subject: str             # Email subject line (like "URGENT: Verify Account!")
    body: str               # Main email content (the actual message text)
    
    # EXTRACTED INFORMATION
    links: List[str]         # All URLs found in the email (like ["http://suspicious.com"])
    domains: List[str]       # All domain names from the links (like ["suspicious.com"])
    
    # TECHNICAL DETAILS
    headers: Dict[str, str]  # Email headers (technical routing info)
    timestamp: Optional[datetime]  # When the email was sent (if available)
    
    def __str__(self) -> str:
        """
        String representation for debugging and logging.
        This makes it easy to print EmailData objects.
        """
        return f"EmailData(sender='{self.sender}', subject='{self.subject[:30]}...', links={len(self.links)})"
    
    def get_summary(self) -> Dict[str, any]:
        """
        Get a summary of the email data for API responses.
        This creates a clean dictionary suitable for JSON responses.
        """
        return {
            'sender': self.sender,
            'subject': self.subject,
            'body_length': len(self.body),
            'links_count': len(self.links),
            'domains_count': len(self.domains),
            'has_headers': bool(self.headers),
            'has_timestamp': self.timestamp is not None
        }

# DETECTION RESULT STRUCTURE
# This is the standardized format that all detection modules output
# Block 2, 3, 4, etc. all return this same structure
@dataclass
class DetectionResult:
    """
    Standardized result from any detection module.
    
    This is what ALL detection modules return - whether it's basic rules,
    pattern matching, ML models, or AI analysis. Having a standard format
    makes it easy to combine results from different modules.
    
    Think of this as a "report card" for how suspicious an email is.
    """
    
    # RISK ASSESSMENT
    risk_score: int          # Risk level from 0-100 (0=safe, 100=definitely phishing)
    classification: str      # Simple category: "Safe", "Suspicious", or "Phishing"
    confidence: float        # How confident we are (0.0-1.0, where 1.0 = very confident)
    
    # EXPLANATIONS
    reasons: List[str]       # List of specific reasons why it's suspicious
    module_name: str         # Which detection module created this result
    
    # METADATA
    timestamp: Optional[datetime] = None  # When this analysis was performed
    
    def __str__(self) -> str:
        """
        String representation for debugging and logging.
        This makes it easy to print DetectionResult objects.
        """
        return f"DetectionResult({self.module_name}: {self.risk_score}/100, {self.classification})"
    
    def get_summary(self) -> Dict[str, any]:
        """
        Get a summary of the detection result for API responses.
        This creates a clean dictionary suitable for JSON responses.
        """
        return {
            'risk_score': self.risk_score,
            'classification': self.classification,
            'confidence': self.confidence,
            'reasons_count': len(self.reasons),
            'module_name': self.module_name,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def is_suspicious(self) -> bool:
        """
        Quick check if this result indicates suspicious activity.
        Returns True if classification is "Suspicious" or "Phishing".
        """
        return self.classification in ["Suspicious", "Phishing"]
    
    def is_high_risk(self) -> bool:
        """
        Quick check if this result indicates high risk.
        Returns True if risk score is 70 or higher.
        """
        return self.risk_score >= 70

# COMBINED ANALYSIS RESULT
# This is used by the Flask API to combine results from multiple detection modules
@dataclass
class CombinedResult:
    """
    Combined results from multiple detection modules.
    
    The Flask API uses this to aggregate results from Block 2, 3, 4, etc.
    and present a unified analysis to the user.
    
    Think of this as a "committee decision" from all our detection modules.
    """
    
    # OVERALL ASSESSMENT
    final_risk_score: int     # Combined risk score from all modules
    final_classification: str # Overall classification based on all modules
    final_confidence: float   # Combined confidence from all modules
    
    # INDIVIDUAL MODULE RESULTS
    module_results: List[DetectionResult]  # Results from each detection module
    
    # COMBINED EXPLANATIONS
    all_reasons: List[str]    # All reasons from all modules combined
    
    # METADATA
    email_summary: Dict[str, any]  # Summary of the original email
    scan_timestamp: datetime       # When this combined analysis was performed
    modules_used: List[str]        # Which detection modules were used
    
    def __str__(self) -> str:
        """String representation for debugging."""
        return f"CombinedResult({self.final_risk_score}/100, {self.final_classification}, {len(self.module_results)} modules)"
    
    def get_api_response(self) -> Dict[str, any]:
        """
        Convert to dictionary suitable for API JSON response.
        This is what the Flask API returns to clients.
        """
        return {
            # Overall results
            'risk_score': self.final_risk_score,
            'classification': self.final_classification,
            'confidence': self.final_confidence,
            'scan_timestamp': self.scan_timestamp.isoformat(),
            
            # Email information
            'email_summary': self.email_summary,
            
            # Module results
            'module_results': [result.get_summary() for result in self.module_results],
            'modules_used': self.modules_used,
            
            # Combined explanations
            'all_reasons': self.all_reasons,
            'total_reasons': len(self.all_reasons)
        }

# UTILITY FUNCTIONS
# These are helper functions for working with our data structures

def create_detection_result(
    risk_score: int,
    classification: str,
    confidence: float,
    reasons: List[str],
    module_name: str
) -> DetectionResult:
    """
    Helper function to create a DetectionResult with automatic timestamp.
    
    This makes it easier for detection modules to create results without
    having to remember to set the timestamp.
    
    Args:
        risk_score: Risk level 0-100
        classification: "Safe", "Suspicious", or "Phishing"
        confidence: Confidence level 0.0-1.0
        reasons: List of specific reasons
        module_name: Name of the detection module
    
    Returns:
        DetectionResult with current timestamp
    """
    return DetectionResult(
        risk_score=risk_score,
        classification=classification,
        confidence=confidence,
        reasons=reasons,
        module_name=module_name,
        timestamp=datetime.now()
    )

def combine_detection_results(
    email_data: EmailData,
    results: List[DetectionResult],
    modules_used: List[str]
) -> CombinedResult:
    """
    Helper function to combine results from multiple detection modules.
    
    This is used by the Flask API to merge results from different detection
    modules into a single unified result.
    
    Args:
        email_data: The original email data
        results: List of results from different detection modules
        modules_used: List of module names that were used
    
    Returns:
        CombinedResult with merged analysis
    """
    if not results:
        # If no results, return a safe default
        return CombinedResult(
            final_risk_score=0,
            final_classification="Safe",
            final_confidence=0.5,
            module_results=[],
            all_reasons=["No detection modules provided results"],
            email_summary=email_data.get_summary(),
            scan_timestamp=datetime.now(),
            modules_used=modules_used
        )
    
    # Calculate combined risk score (average of all modules)
    total_risk = sum(result.risk_score for result in results)
    avg_risk = total_risk // len(results)
    final_risk_score = min(avg_risk, 100)  # Cap at 100
    
    # Determine final classification (use the highest risk result)
    highest_risk_result = max(results, key=lambda r: r.risk_score)
    final_classification = highest_risk_result.classification
    
    # Calculate combined confidence (use the highest confidence)
    final_confidence = max(result.confidence for result in results)
    
    # Combine all reasons from all modules
    all_reasons = []
    for result in results:
        all_reasons.extend(result.reasons)
    
    # Create and return the combined result
    return CombinedResult(
        final_risk_score=final_risk_score,
        final_classification=final_classification,
        final_confidence=final_confidence,
        module_results=results,
        all_reasons=all_reasons,
        email_summary=email_data.get_summary(),
        scan_timestamp=datetime.now(),
        modules_used=modules_used
    )

def validate_email_data(email_data: EmailData) -> bool:
    """
    Validate that EmailData contains the minimum required information.
    
    This is used by detection modules to make sure they received valid data.
    
    Args:
        email_data: EmailData object to validate
    
    Returns:
        True if valid, False otherwise
    """
    # Check that all required fields are present and not empty
    if not email_data.sender or not isinstance(email_data.sender, str):
        return False
    
    if not email_data.subject or not isinstance(email_data.subject, str):
        return False
    
    if not email_data.body or not isinstance(email_data.body, str):
        return False
    
    if not isinstance(email_data.links, list):
        return False
    
    if not isinstance(email_data.domains, list):
        return False
    
    if not isinstance(email_data.headers, dict):
        return False
    
    return True

def validate_detection_result(result: DetectionResult) -> bool:
    """
    Validate that DetectionResult contains valid data.
    
    This is used by the Flask API to make sure detection modules returned
    valid results.
    
    Args:
        result: DetectionResult object to validate
    
    Returns:
        True if valid, False otherwise
    """
    # Check risk score is in valid range
    if not isinstance(result.risk_score, int) or result.risk_score < 0 or result.risk_score > 100:
        return False
    
    # Check classification is one of the allowed values
    if result.classification not in ["Safe", "Suspicious", "Phishing"]:
        return False
    
    # Check confidence is in valid range
    if not isinstance(result.confidence, float) or result.confidence < 0.0 or result.confidence > 1.0:
        return False
    
    # Check reasons is a list of strings
    if not isinstance(result.reasons, list):
        return False
    
    for reason in result.reasons:
        if not isinstance(reason, str):
            return False
    
    # Check module name is present
    if not result.module_name or not isinstance(result.module_name, str):
        return False
    
    return True

# CONSTANTS
# These are standard values used throughout the system

# Risk score thresholds
RISK_THRESHOLD_LOW = 30      # Below this = "Safe"
RISK_THRESHOLD_HIGH = 70     # Above this = "Phishing"
                            # Between = "Suspicious"

# Confidence thresholds
CONFIDENCE_LOW = 0.5        # Below this = low confidence
CONFIDENCE_HIGH = 0.8       # Above this = high confidence

# Default values
DEFAULT_RISK_SCORE = 0
DEFAULT_CLASSIFICATION = "Safe"
DEFAULT_CONFIDENCE = 0.5
DEFAULT_MODULE_NAME = "UnknownModule"

# Maximum limits
MAX_LINKS_PER_EMAIL = 1000      # Maximum links to process per email
MAX_DOMAINS_PER_EMAIL = 100     # Maximum domains to process per email
MAX_REASONS_PER_RESULT = 50     # Maximum reasons per detection result
MAX_BODY_LENGTH = 1000000       # Maximum email body length (1MB)

if __name__ == "__main__":
    # Simple test when running this file directly
    from datetime import datetime
    
    print("=== Data Models Test ===")
    
    # Test EmailData creation
    test_email = EmailData(
        sender="test@example.com",
        subject="Test Email",
        body="This is a test email body",
        links=["https://example.com"],
        domains=["example.com"],
        headers={"From": "test@example.com"},
        timestamp=datetime.now()
    )
    
    print(f"Created EmailData: {test_email}")
    print(f"Email Summary: {test_email.get_summary()}")
    
    # Test DetectionResult creation
    test_result = create_detection_result(
        risk_score=45,
        classification="Suspicious",
        confidence=0.75,
        reasons=["Test reason 1", "Test reason 2"],
        module_name="TestModule"
    )
    
    print(f"Created DetectionResult: {test_result}")
    print(f"Result Summary: {test_result.get_summary()}")
    print(f"Is suspicious: {test_result.is_suspicious()}")
    print(f"Is high risk: {test_result.is_high_risk()}")
    
    # Test validation
    print(f"EmailData valid: {validate_email_data(test_email)}")
    print(f"DetectionResult valid: {validate_detection_result(test_result)}")
    
    print("=== Models test complete ===") 