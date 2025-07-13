"""
AI URL Detector - Block 6
This module uses a pre-trained XGBoost model to classify URLs as phishing or benign.
It processes the links found in emails and returns predictions for each URL.
"""

import os
import logging
from typing import Dict, List, Optional, Tuple
import joblib
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer

# Set up logging
logger = logging.getLogger(__name__)

class AIURLDetector:
    """
    AI-powered URL classifier using XGBoost.
    
    This class loads a pre-trained XGBoost model and TF-IDF vectorizer
    to classify URLs as phishing (1) or benign (0).
    """
    
    def __init__(self, model_path: str = "url_phishing_xgb_tiny.pkl"):
        """
        Initialize the AI URL detector.
        
        Args:
            model_path: Path to the pickled model file containing vectorizer and booster
        """
        self.model_path = model_path
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.booster: Optional[xgb.Booster] = None
        self.is_loaded = False
        
        # Try to load the model during initialization
        self._load_model()
    
    def _load_model(self) -> bool:
        """
        Load the XGBoost model and vectorizer from the pickle file.
        
        Returns:
            bool: True if model loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                return False
            
            logger.info(f"Loading AI model from: {self.model_path}")
            
            # Load the vectorizer and booster from the pickle file
            self.vectorizer, self.booster = joblib.load(self.model_path)
            
            # Verify that we got the expected objects
            if not isinstance(self.vectorizer, TfidfVectorizer):
                logger.error("Loaded vectorizer is not a TfidfVectorizer")
                return False
            
            if not hasattr(self.booster, 'predict'):
                logger.error("Loaded booster does not have a predict method")
                return False
            
            self.is_loaded = True
            logger.info("AI model loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load AI model: {str(e)}")
            self.is_loaded = False
            return False
    
    def predict_url(self, url: str, threshold: float = 0.5) -> Tuple[int, float]:
        """
        Predict if a single URL is phishing or benign.
        
        Args:
            url: The URL to classify
            threshold: Probability threshold for classification (default 0.5)
            
        Returns:
            Tuple of (prediction, probability) where:
            - prediction: 1 for phishing, 0 for benign
            - probability: Probability of being phishing (0.0-1.0)
        """
        if not self.is_loaded or self.vectorizer is None or self.booster is None:
            logger.warning("Model not loaded, attempting to reload...")
            if not self._load_model():
                logger.error("Failed to load model for prediction")
                return 0, 0.0
        
        # At this point, we know the model is loaded and vectorizer/booster are not None
        assert self.vectorizer is not None
        assert self.booster is not None
        
        try:
            # Vectorize the URL
            X_url = self.vectorizer.transform([url])
            
            # Create XGBoost DMatrix
            dtest = xgb.DMatrix(X_url)
            
            # Get prediction probability
            probas = self.booster.predict(dtest)
            probability = float(probas[0]) if probas is not None and len(probas) > 0 else 0.0
            
            # Convert probability to binary prediction
            prediction = 1 if probability >= threshold else 0
            
            return prediction, probability
            
        except Exception as e:
            logger.error(f"Error predicting URL '{url}': {str(e)}")
            return 0, 0.0
    
    def predict_urls(self, urls: List[str], threshold: float = 0.5) -> Dict[str, Dict[str, any]]:
        """
        Predict multiple URLs in batch.
        
        Args:
            urls: List of URLs to classify
            threshold: Probability threshold for classification (default 0.5)
            
        Returns:
            Dictionary mapping each URL to its prediction results:
            {
                "url": {
                    "prediction": 1,      # 1 for phishing, 0 for benign
                    "probability": 0.85,  # Probability of being phishing
                    "classification": "Phishing"  # Human-readable classification
                }
            }
        """
        if not urls:
            logger.warning("No URLs provided for prediction")
            return {}
        
        if not self.is_loaded or self.vectorizer is None or self.booster is None:
            logger.warning("Model not loaded, attempting to reload...")
            if not self._load_model():
                logger.error("Failed to load model for batch prediction")
                return {url: {"prediction": 0, "probability": 0.0, "classification": "Unknown"} for url in urls}
        
        # At this point, we know the model is loaded and vectorizer/booster are not None
        assert self.vectorizer is not None
        assert self.booster is not None
        
        results = {}
        
        try:
            # Vectorize all URLs at once for efficiency
            X_urls = self.vectorizer.transform(urls)
            
            # Create XGBoost DMatrix
            dtest = xgb.DMatrix(X_urls)
            
            # Get prediction probabilities for all URLs
            probas = self.booster.predict(dtest)
            
            # Process results for each URL
            for i, url in enumerate(urls):
                try:
                    probability = float(probas[i]) if i < len(probas) else 0.0
                    prediction = 1 if probability >= threshold else 0
                    
                    # Human-readable classification
                    if prediction == 1:
                        if probability >= 0.8:
                            classification = "Phishing"
                        else:
                            classification = "Suspicious"
                    else:
                        classification = "Benign"
                    
                    results[url] = {
                        "prediction": prediction,
                        "probability": probability,
                        "classification": classification
                    }
                    
                except Exception as e:
                    logger.error(f"Error processing URL '{url}': {str(e)}")
                    results[url] = {
                        "prediction": 0,
                        "probability": 0.0,
                        "classification": "Error"
                    }
            
            logger.info(f"Processed {len(urls)} URLs with AI detection")
            return results
            
        except Exception as e:
            logger.error(f"Error in batch URL prediction: {str(e)}")
            # Return default results for all URLs
            return {url: {"prediction": 0, "probability": 0.0, "classification": "Error"} for url in urls}
    
    def get_model_info(self) -> Dict[str, any]:
        """
        Get information about the loaded model.
        
        Returns:
            Dictionary with model information
        """
        return {
            "model_path": self.model_path,
            "is_loaded": self.is_loaded,
            "model_exists": os.path.exists(self.model_path),
            "vectorizer_type": type(self.vectorizer).__name__ if self.vectorizer else None,
            "booster_type": type(self.booster).__name__ if self.booster else None
        }

# Global instance for easy access
_ai_detector = None

def get_ai_detector() -> AIURLDetector:
    """
    Get the global AI detector instance (singleton pattern).
    
    Returns:
        AIURLDetector: The global detector instance
    """
    global _ai_detector
    if _ai_detector is None:
        _ai_detector = AIURLDetector()
    return _ai_detector

def detect_ai_urls(urls: List[str], threshold: float = 0.5) -> Dict[str, Dict[str, any]]:
    """
    Convenience function to detect URLs using the global AI detector.
    
    Args:
        urls: List of URLs to classify
        threshold: Probability threshold for classification (default 0.5)
        
    Returns:
        Dictionary mapping URLs to their predictions
    """
    detector = get_ai_detector()
    return detector.predict_urls(urls, threshold)

# Example usage and testing
if __name__ == "__main__":
    # Set up logging for testing
    logging.basicConfig(level=logging.INFO)
    
    # Test URLs
    test_urls = [
        "http://secure-login-paypal.com/update/account-verification",
        "https://www.wikipedia.org/",
        "https://www.google.com/",
        "http://phishing-site.suspicious.com/steal-credentials"
    ]
    
    # Test the detector
    print("Testing AI URL Detector")
    print("=" * 50)
    
    detector = AIURLDetector()
    
    if detector.is_loaded:
        results = detector.predict_urls(test_urls)
        
        for url, result in results.items():
            pred = result["prediction"]
            prob = result["probability"]
            classification = result["classification"]
            print(f"{url:60} → {classification:12} (pred={pred}, p={prob:.3f})")
    else:
        print("Failed to load AI model")
    
    print("\nModel info:")
    print(detector.get_model_info()) 
