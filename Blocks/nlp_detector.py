"""
NLP-Based Detection Module - Block 5
Uses Natural Language Processing to detect phishing through language analysis.
This module analyzes emotional manipulation, sentiment, grammar, and language authenticity.
"""

import re
import nltk
from textblob import TextBlob
from typing import List, Dict, Tuple, Optional
from collections import Counter
from models import EmailData, DetectionResult
import logging

# Download required NLTK data (only runs once)
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)

from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize, sent_tokenize

# Set up logging
logger = logging.getLogger(__name__)


class NLPDetector:
    """
    NLP-based phishing detector that analyzes language patterns.
    
    This detector uses Natural Language Processing to identify:
    1. Emotional manipulation (fear, urgency, desperation)
    2. Sentiment analysis (negative emotions)
    3. Grammar and spelling quality
    4. Language authenticity (does it sound natural?)
    5. Psychological pressure tactics
    """
    
    def __init__(self):
        """Initialize the NLP detector with language analysis tools."""
        
        # Get English stopwords for text analysis
        try:
            self.stopwords = set(stopwords.words('english'))
        except Exception:
            # Fallback if NLTK data isn't available
            self.stopwords = set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'])
        
        # EMOTIONAL MANIPULATION PATTERNS
        # These words are designed to create specific emotional responses
        self.fear_words = {
            # Direct fear and threat words
            'danger', 'threat', 'risk', 'warning', 'alert', 'caution', 'beware',
            'unsafe', 'vulnerable', 'exposed', 'compromised', 'breach', 'attack',
            'stolen', 'fraud', 'scam', 'illegal', 'criminal', 'unauthorized',
            
            # Consequence words (what bad things will happen)
            'suspended', 'closed', 'terminated', 'cancelled', 'blocked', 'banned',
            'penalty', 'fine', 'charge', 'fee', 'loss', 'lose', 'lost',
            'permanent', 'forever', 'irreversible', 'damage', 'harm'
        }
        
        self.urgency_words = {
            # Time pressure words
            'urgent', 'immediate', 'instantly', 'now', 'quickly', 'asap',
            'deadline', 'expires', 'expiring', 'limited', 'ending', 'final',
            'last', 'hurry', 'rush', 'fast', 'speed', 'prompt',
            
            # Action demand words
            'must', 'required', 'mandatory', 'essential', 'critical', 'vital',
            'important', 'necessary', 'demanded', 'forced', 'compelled'
        }
        
        self.desperation_words = {
            # Help and plea words
            'help', 'please', 'urgent', 'emergency', 'crisis', 'desperate',
            'stuck', 'trapped', 'need', 'require', 'beg', 'plead',
            
            # Emotional appeal words
            'family', 'children', 'sick', 'dying', 'hospital', 'medical',
            'money', 'financial', 'debt', 'bankruptcy', 'homeless'
        }
        
        # PSYCHOLOGICAL PRESSURE TACTICS
        # These patterns are used to manipulate people psychologically
        self.authority_words = {
            # Official sounding words
            'official', 'government', 'legal', 'court', 'police', 'fbi',
            'irs', 'tax', 'department', 'agency', 'administration',
            'security', 'compliance', 'regulation', 'policy', 'law',
            
            # Corporate authority words
            'management', 'executive', 'director', 'admin', 'supervisor',
            'headquarters', 'corporate', 'official', 'authorized'
        }
        
        self.scarcity_words = {
            # Limited availability words
            'limited', 'exclusive', 'rare', 'special', 'unique', 'one-time',
            'only', 'last', 'final', 'remaining', 'few', 'running out',
            'disappear', 'gone', 'miss', 'opportunity', 'chance'
        }
        
        # COMMON GRAMMAR MISTAKES IN PHISHING
        # These patterns often indicate non-native speakers
        self.grammar_error_patterns = [
            r'\b(me|I) are\b',           # "me are" instead of "I am"
            r'\b(we|you|they) is\b',     # "we is" instead of "we are"
            r'\ban\s+[^aeiou]',          # "an" before consonant
            r'\ba\s+[aeiou]',            # "a" before vowel
            r'\bvery\s+much\s+',         # "very much" in wrong context
            r'\bmake\s+to\s+',           # "make to" instead of proper infinitive
            r'\bmore\s+better\b',        # "more better" (double comparative)
            r'\bmost\s+easiest\b',       # "most easiest" (double superlative)
        ]
        
        # SPELLING ERROR INDICATORS
        # Common misspellings in phishing emails
        self.common_misspellings = {
            'recieve': 'receive', 'seperate': 'separate', 'occured': 'occurred',
            'priviledge': 'privilege', 'necesary': 'necessary', 'accont': 'account',
            'importent': 'important', 'secuirty': 'security', 'verfiy': 'verify',
            'paypal': 'PayPal', 'amazone': 'Amazon', 'mircosoft': 'Microsoft'
        }
        
        # UNNATURAL LANGUAGE PATTERNS
        # These patterns sound robotic or translated
        self.unnatural_patterns = [
            r'\bkindly\s+',              # "Kindly" is overused by scammers
            r'\bdo\s+needful\b',         # "do the needful" (non-native phrase)
            r'\brevert\s+back\b',        # "revert back" (redundant)
            r'\bgood\s+day\b',           # "good day" (formal greeting)
            r'\bthanks\s+and\s+regards\b', # Common scammer sign-off
            r'\bhope\s+you\s+are\s+fine\b', # Common scammer opening
        ]
        
        # FINANCIAL SCAM INDICATORS
        # Words that indicate financial scams
        self.financial_scam_words = {
            'lottery', 'winner', 'jackpot', 'prize', 'reward', 'bonus',
            'inheritance', 'beneficiary', 'will', 'estate', 'deceased',
            'million', 'billions', 'dollars', 'pounds', 'euros',
            'transfer', 'wire', 'swift', 'bank', 'account', 'funds',
            'deposit', 'withdraw', 'fee', 'tax', 'clearance', 'processing'
        }
    
    def analyze(self, email_data: EmailData) -> DetectionResult:
        """
        Main NLP analysis function.
        
        This function performs comprehensive language analysis on the email
        to detect emotional manipulation and linguistic red flags.
        
        Args:
            email_data (EmailData): Parsed email data from Block 1
            
        Returns:
            DetectionResult: NLP analysis results
        """
        # Start with zero risk
        risk_score = 0
        reasons = []
        
        # Combine subject and body for analysis
        full_text = f"{email_data.subject} {email_data.body}"
        
        # TEST 1: Emotional Manipulation Analysis
        # Check if the email tries to manipulate emotions
        emotion_risk, emotion_reasons = self._analyze_emotional_manipulation(full_text)
        risk_score += emotion_risk
        reasons.extend(emotion_reasons)
        
        # TEST 2: Sentiment Analysis
        # Analyze overall sentiment and emotional tone
        sentiment_risk, sentiment_reasons = self._analyze_sentiment(full_text)
        risk_score += sentiment_risk
        reasons.extend(sentiment_reasons)
        
        # TEST 3: Grammar and Spelling Analysis
        # Check for grammar mistakes and spelling errors
        grammar_risk, grammar_reasons = self._analyze_grammar_quality(full_text)
        risk_score += grammar_risk
        reasons.extend(grammar_reasons)
        
        # TEST 4: Language Authenticity Check
        # Check if language sounds natural or robotic/translated
        authenticity_risk, authenticity_reasons = self._analyze_language_authenticity(full_text)
        risk_score += authenticity_risk
        reasons.extend(authenticity_reasons)
        
        # TEST 5: Psychological Pressure Analysis
        # Check for pressure tactics and manipulation techniques
        pressure_risk, pressure_reasons = self._analyze_psychological_pressure(full_text)
        risk_score += pressure_risk
        reasons.extend(pressure_reasons)
        
        # TEST 6: Financial Scam Detection
        # Check for financial scam indicators
        financial_risk, financial_reasons = self._analyze_financial_scam_patterns(full_text)
        risk_score += financial_risk
        reasons.extend(financial_reasons)
        
        # TEST 7: Text Complexity Analysis
        # Check if text complexity is appropriate for the claimed sender
        complexity_risk, complexity_reasons = self._analyze_text_complexity(full_text)
        risk_score += complexity_risk
        reasons.extend(complexity_reasons)
        
        # Cap risk score at 100
        risk_score = min(risk_score, 100)
        
        # Determine classification
        if risk_score >= 80:
            classification = "Phishing"
            confidence = 0.90
        elif risk_score >= 50:
            classification = "Suspicious"
            confidence = 0.75
        else:
            classification = "Safe"
            confidence = 0.70
        
        return DetectionResult(
            risk_score=risk_score,
            classification=classification,
            confidence=confidence,
            reasons=reasons,
            module_name="NLPDetector"
        )
    
    def _analyze_emotional_manipulation(self, text: str) -> Tuple[int, List[str]]:
        """
        TEST 1: Analyze emotional manipulation tactics.
        
        Phishing emails often use fear, urgency, and desperation to manipulate victims.
        """
        risk = 0
        reasons = []
        text_lower = text.lower()
        
        # Check for fear-inducing words
        fear_count = sum(1 for word in self.fear_words if word in text_lower)
        if fear_count >= 3:
            risk += 25
            reasons.append(f"High fear-inducing language: {fear_count} fear words detected")
        elif fear_count >= 1:
            risk += 10
            reasons.append(f"Fear-inducing language detected: {fear_count} fear words")
        
        # Check for urgency words
        urgency_count = sum(1 for word in self.urgency_words if word in text_lower)
        if urgency_count >= 4:
            risk += 30
            reasons.append(f"Excessive urgency language: {urgency_count} urgency words")
        elif urgency_count >= 2:
            risk += 15
            reasons.append(f"Urgency language detected: {urgency_count} urgency words")
        
        # Check for desperation words
        desperation_count = sum(1 for word in self.desperation_words if word in text_lower)
        if desperation_count >= 2:
            risk += 20
            reasons.append(f"Desperation language detected: {desperation_count} desperation words")
        
        # Check for combined emotional manipulation
        total_emotion_words = fear_count + urgency_count + desperation_count
        if total_emotion_words >= 6:
            risk += 15
            reasons.append(f"Heavy emotional manipulation: {total_emotion_words} total emotion words")
        
        return risk, reasons
    
    def _analyze_sentiment(self, text: str) -> Tuple[int, List[str]]:
        """
        TEST 2: Analyze sentiment and emotional tone.
        
        Phishing emails often have negative sentiment and emotional extremes.
        """
        risk = 0
        reasons = []
        
        try:
            # Use TextBlob for sentiment analysis
            blob = TextBlob(text)
            sentiment_score = blob.sentiment.polarity  # -1 (negative) to 1 (positive)
            subjectivity = blob.sentiment.subjectivity  # 0 (objective) to 1 (subjective)
            
            # Check for extremely negative sentiment
            if sentiment_score < -0.5:
                risk += 20
                reasons.append(f"Extremely negative sentiment: {sentiment_score:.2f}")
            elif sentiment_score < -0.2:
                risk += 10
                reasons.append(f"Negative sentiment detected: {sentiment_score:.2f}")
            
            # Check for high subjectivity (emotional language)
            if subjectivity > 0.7:
                risk += 15
                reasons.append(f"Highly emotional language: {subjectivity:.2f} subjectivity")
            elif subjectivity > 0.5:
                risk += 8
                reasons.append(f"Emotional language detected: {subjectivity:.2f} subjectivity")
            
            # Check for extreme sentiment swings in different sentences
            sentences = sent_tokenize(text)
            if len(sentences) > 1:
                sentence_sentiments = [TextBlob(sentence).sentiment.polarity for sentence in sentences]
                sentiment_range = max(sentence_sentiments) - min(sentence_sentiments)
                
                if sentiment_range > 1.5:
                    risk += 12
                    reasons.append(f"Extreme sentiment swings detected: range {sentiment_range:.2f}")
                
        except Exception as e:
            logger.warning(f"Sentiment analysis failed: {e}")
        
        return risk, reasons
    
    def _analyze_grammar_quality(self, text: str) -> Tuple[int, List[str]]:
        """
        TEST 3: Analyze grammar and spelling quality.
        
        Phishing emails often have poor grammar and spelling mistakes.
        """
        risk = 0
        reasons = []
        text_lower = text.lower()
        
        # Check for grammar error patterns
        grammar_errors = 0
        for pattern in self.grammar_error_patterns:
            matches = re.findall(pattern, text_lower)
            grammar_errors += len(matches)
        
        if grammar_errors >= 3:
            risk += 25
            reasons.append(f"Multiple grammar errors detected: {grammar_errors} errors")
        elif grammar_errors >= 1:
            risk += 12
            reasons.append(f"Grammar errors detected: {grammar_errors} errors")
        
        # Check for common misspellings
        spelling_errors = 0
        words = word_tokenize(text_lower)
        for word in words:
            if word in self.common_misspellings:
                spelling_errors += 1
        
        if spelling_errors >= 2:
            risk += 20
            reasons.append(f"Multiple spelling errors: {spelling_errors} misspellings")
        elif spelling_errors >= 1:
            risk += 10
            reasons.append(f"Spelling errors detected: {spelling_errors} misspellings")
        
        # Check for excessive punctuation (!!!, ???)
        excessive_punct = len(re.findall(r'[!?]{3,}', text))
        if excessive_punct > 0:
            risk += 8
            reasons.append(f"Excessive punctuation usage: {excessive_punct} instances")
        
        # Check for ALL CAPS usage
        caps_words = len(re.findall(r'\b[A-Z]{3,}\b', text))
        total_words = len(word_tokenize(text))
        if total_words > 0:
            caps_ratio = caps_words / total_words
            if caps_ratio > 0.2:
                risk += 15
                reasons.append(f"Excessive capitalization: {caps_ratio:.1%} of words in caps")
        
        return risk, reasons
    
    def _analyze_language_authenticity(self, text: str) -> Tuple[int, List[str]]:
        """
        TEST 4: Check if language sounds natural or robotic/translated.
        
        Phishing emails often use unnatural language patterns.
        """
        risk = 0
        reasons = []
        text_lower = text.lower()
        
        # Check for unnatural language patterns
        unnatural_count = 0
        for pattern in self.unnatural_patterns:
            matches = re.findall(pattern, text_lower)
            unnatural_count += len(matches)
        
        if unnatural_count >= 2:
            risk += 20
            reasons.append(f"Multiple unnatural language patterns: {unnatural_count} patterns")
        elif unnatural_count >= 1:
            risk += 10
            reasons.append(f"Unnatural language patterns detected: {unnatural_count} patterns")
        
        # Check for repetitive phrases
        sentences = sent_tokenize(text)
        if len(sentences) > 1:
            # Look for repeated phrases
            phrase_counts = Counter()
            for sentence in sentences:
                words = word_tokenize(sentence.lower())
                # Check for repeated 3-word phrases
                for i in range(len(words) - 2):
                    phrase = ' '.join(words[i:i+3])
                    phrase_counts[phrase] += 1
            
            repeated_phrases = [phrase for phrase, count in phrase_counts.items() if count > 1]
            if len(repeated_phrases) > 0:
                risk += 12
                reasons.append(f"Repetitive language patterns: {len(repeated_phrases)} repeated phrases")
        
        # Check for overly formal language in informal contexts
        formal_words = ['kindly', 'hereby', 'henceforth', 'aforementioned', 'pursuant']
        formal_count = sum(1 for word in formal_words if word in text_lower)
        if formal_count >= 2:
            risk += 10
            reasons.append(f"Overly formal language: {formal_count} formal words")
        
        return risk, reasons
    
    def _analyze_psychological_pressure(self, text: str) -> Tuple[int, List[str]]:
        """
        TEST 5: Analyze psychological pressure tactics.
        
        Phishing emails use authority and scarcity to pressure victims.
        """
        risk = 0
        reasons = []
        text_lower = text.lower()
        
        # Check for authority words
        authority_count = sum(1 for word in self.authority_words if word in text_lower)
        if authority_count >= 3:
            risk += 20
            reasons.append(f"Heavy authority language: {authority_count} authority words")
        elif authority_count >= 1:
            risk += 10
            reasons.append(f"Authority language detected: {authority_count} authority words")
        
        # Check for scarcity words
        scarcity_count = sum(1 for word in self.scarcity_words if word in text_lower)
        if scarcity_count >= 3:
            risk += 18
            reasons.append(f"Strong scarcity tactics: {scarcity_count} scarcity words")
        elif scarcity_count >= 1:
            risk += 8
            reasons.append(f"Scarcity tactics detected: {scarcity_count} scarcity words")
        
        # Check for social proof manipulation
        social_proof_patterns = [
            r'thousands of', r'millions of', r'most people', r'everyone is',
            r'join now', r'don\'t be left', r'others have'
        ]
        social_proof_count = sum(1 for pattern in social_proof_patterns if re.search(pattern, text_lower))
        if social_proof_count >= 1:
            risk += 10
            reasons.append(f"Social proof manipulation: {social_proof_count} patterns")
        
        return risk, reasons
    
    def _analyze_financial_scam_patterns(self, text: str) -> Tuple[int, List[str]]:
        """
        TEST 6: Check for financial scam indicators.
        
        Many phishing emails are financial scams.
        """
        risk = 0
        reasons = []
        text_lower = text.lower()
        
        # Check for financial scam words
        financial_count = sum(1 for word in self.financial_scam_words if word in text_lower)
        if financial_count >= 5:
            risk += 30
            reasons.append(f"Strong financial scam indicators: {financial_count} financial terms")
        elif financial_count >= 3:
            risk += 20
            reasons.append(f"Financial scam indicators: {financial_count} financial terms")
        elif financial_count >= 1:
            risk += 10
            reasons.append(f"Financial terms detected: {financial_count} terms")
        
        # Check for specific financial scam patterns
        scam_patterns = [
            r'you have won', r'congratulations.*winner', r'claim.*prize',
            r'inheritance.*million', r'transfer.*funds', r'beneficiary',
            r'lottery.*winner', r'jackpot.*won'
        ]
        scam_pattern_count = sum(1 for pattern in scam_patterns if re.search(pattern, text_lower))
        if scam_pattern_count >= 1:
            risk += 25
            reasons.append(f"Financial scam patterns detected: {scam_pattern_count} patterns")
        
        # Check for large monetary amounts
        money_patterns = re.findall(r'[\$£€]\s*\d+(?:,\d{3})*(?:\.\d{2})?', text)
        money_patterns.extend(re.findall(r'\d+(?:,\d{3})*\s*(?:million|billion|thousand)\s*(?:dollars|pounds|euros)', text_lower))
        
        if len(money_patterns) >= 2:
            risk += 15
            reasons.append(f"Multiple monetary amounts mentioned: {len(money_patterns)} amounts")
        
        return risk, reasons
    
    def _analyze_text_complexity(self, text: str) -> Tuple[int, List[str]]:
        """
        TEST 7: Analyze text complexity and readability.
        
        Phishing emails often have inconsistent complexity patterns.
        """
        risk = 0
        reasons = []
        
        try:
            # Basic complexity metrics
            words = word_tokenize(text)
            sentences = sent_tokenize(text)
            
            if len(sentences) == 0 or len(words) == 0:
                return risk, reasons
            
            # Average words per sentence
            avg_words_per_sentence = len(words) / len(sentences)
            
            # Check for extremely short or long sentences
            if avg_words_per_sentence < 5:
                risk += 8
                reasons.append(f"Extremely short sentences: {avg_words_per_sentence:.1f} words per sentence")
            elif avg_words_per_sentence > 30:
                risk += 10
                reasons.append(f"Extremely long sentences: {avg_words_per_sentence:.1f} words per sentence")
            
            # Check for inconsistent sentence structure
            sentence_lengths = [len(word_tokenize(sentence)) for sentence in sentences]
            if len(sentence_lengths) > 1:
                length_variance = max(sentence_lengths) - min(sentence_lengths)
                if length_variance > 20:
                    risk += 5
                    reasons.append(f"Inconsistent sentence structure: variance {length_variance}")
            
            # Check for very simple vocabulary (possible translation)
            complex_words = [word for word in words if len(word) > 6]
            if len(words) > 0:
                complex_ratio = len(complex_words) / len(words)
                if complex_ratio < 0.1:
                    risk += 8
                    reasons.append(f"Very simple vocabulary: {complex_ratio:.1%} complex words")
        
        except Exception as e:
            logger.warning(f"Text complexity analysis failed: {e}")
        
        return risk, reasons


# Convenience function for quick NLP detection
def detect_nlp_patterns(email_data: EmailData) -> DetectionResult:
    """
    Quick function to detect NLP patterns without creating a detector instance.
    
    Args:
        email_data (EmailData): Parsed email data
        
    Returns:
        DetectionResult: NLP detection result
    """
    detector = NLPDetector()
    return detector.analyze(email_data)


if __name__ == "__main__":
    # Test the NLP detector
    from email_parser import parse_email
    
    # Test with an emotionally manipulative phishing email
    test_email = """From: urgent-security@bank-alert.com
Subject: URGENT!!! Your account will be CLOSED FOREVER!!!

Dear valued customer,

We are writing to inform you that your account has been compromised and will be permanently suspended unless you take immediate action. This is a final warning!

Kindly revert back to us with your complete account details including:
- Username and password
- Social Security Number
- Credit card information

You must act now! Do not delay! If you don't respond within 24 hours, you will lose access to your account forever and all your money will be gone.

This is very urgent matter. Please help us to verify your identity immediately. Time is running out!

Thanks and regards,
Security Department
(This is obviously fake)
"""
    
    # Parse and analyze with NLP detector
    email_data = parse_email(test_email)
    result = detect_nlp_patterns(email_data)
    
    print("=== NLP Detector Test ===")
    print(f"Risk Score: {result.risk_score}/100")
    print(f"Classification: {result.classification}")
    print(f"Confidence: {result.confidence:.2f}")
    print("NLP Analysis Results:")
    for reason in result.reasons:
        print(f"  - {reason}") 