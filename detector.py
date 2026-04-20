"""
Smishing Detection Module
Uses Hugging Face Inference API instead of loading model locally
"""

import os
import requests
from config import Config


class SmishingDetector:
    """Smishing detector using HF Inference API"""

    def __init__(self, model_path=None, min_word_length=None):
        """Initialize smishing detector"""
        self.model_path = model_path or Config.MODEL_PATH
        self.MIN_WORD_LENGTH = min_word_length or Config.MIN_WORD_LENGTH
        self.hf_token = os.environ.get("HF_TOKEN", "")
        self.api_url = f"https://api-inference.huggingface.co/models/{self.model_path}"
        self.headers = {"Authorization": f"Bearer {self.hf_token}"}
        self.model_loaded = True
        print("HF Inference API ready")

    def categorize_confidence(self, confidence):
        """Categorize confidence level"""
        if confidence >= 0.9:
            return "VERY HIGH"
        elif confidence >= 0.75:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"

    def check_harmful_urls(self, url_scan_results):
        """Check if any URLs are flagged as harmful"""
        if not url_scan_results:
            return False, []
        harmful_urls = []
        for result in url_scan_results:
            if result.get('is_harmful', False):
                harmful_urls.append(result)
        return len(harmful_urls) > 0, harmful_urls

    def predict(self, text, include_lime=True, url_scan_results=None):
        """Main prediction method with URL priority"""

        # PRIORITY CHECK: Harmful URLs override everything
        has_harmful_urls, harmful_url_list = self.check_harmful_urls(url_scan_results)
        if has_harmful_urls:
            print(f"⚠️ HARMFUL URL DETECTED - Overriding model prediction")
            total_malicious = sum(url.get('malicious_count', 0) for url in harmful_url_list)
            total_suspicious = sum(url.get('suspicious_count', 0) for url in harmful_url_list)

            if total_malicious >= 3:
                confidence = 0.95
            elif total_malicious >= 1:
                confidence = 0.90
            else:
                confidence = 0.85

            return {
                'prediction': 'smishing',
                'confidence': float(confidence),
                'confidence_level': self.categorize_confidence(confidence),
                'probabilities': {
                    'ham': float(1 - confidence),
                    'smishing': float(confidence)
                },
                'model_used': 'VirusTotal URL Analysis (Harmful URL Detected)',
                'url_override': True,
                'harmful_url_details': {
                    'count': len(harmful_url_list),
                    'total_malicious_flags': total_malicious,
                    'total_suspicious_flags': total_suspicious
                }
            }

        # Call HF Inference API
        try:
            response = requests.post(
                self.api_url,
                headers=self.headers,
                json={"inputs": text},
                timeout=30
            )
            result = response.json()

            # HF returns [[{label, score}, {label, score}]]
            if isinstance(result, list) and len(result) > 0:
                scores = result[0] if isinstance(result[0], list) else result
            else:
                raise ValueError(f"Unexpected API response: {result}")

            # Find smishing and ham scores
            smishing_score = None
            ham_score = None
            for item in scores:
                label = item['label'].lower()
                if label in ['smish', 'smishing', '1', 'label_1']:
                    smishing_score = item['score']
                else:
                    ham_score = item['score']

            if smishing_score is None:
                smishing_score = 1 - (ham_score or 0.5)
            if ham_score is None:
                ham_score = 1 - smishing_score

            if smishing_score > 0.5:
                prediction = 'smishing'
                confidence = smishing_score
            else:
                prediction = 'ham'
                confidence = ham_score

            return {
                'prediction': prediction,
                'confidence': float(confidence),
                'confidence_level': self.categorize_confidence(confidence),
                'probabilities': {
                    'ham': float(ham_score),
                    'smishing': float(smishing_score)
                },
                'model_used': 'Fine-tuned DistilBERT (via HF API)',
                'url_override': False
            }

        except Exception as e:
            print(f"HF API error: {e}")
            return self.fallback_predict(text, url_scan_results)

    def fallback_predict(self, text, url_scan_results=None):
        """Fallback prediction when API unavailable"""
        has_harmful_urls, harmful_url_list = self.check_harmful_urls(url_scan_results)

        if has_harmful_urls:
            prediction = 'smishing'
            confidence = 0.85
            model_used = 'Rule-based Fallback (Harmful URL Detected)'
        else:
            text_lower = text.lower()
            suspicious_keywords = ['urgent', 'verify', 'suspended', 'click', 'confirm', 'immediately']
            keyword_count = sum(1 for kw in suspicious_keywords if kw in text_lower)

            if keyword_count >= 3:
                prediction = 'smishing'
                confidence = 0.70
            else:
                prediction = 'ham'
                confidence = 0.60
            model_used = 'Rule-based Fallback'

        return {
            'prediction': prediction,
            'confidence': float(confidence),
            'confidence_level': self.categorize_confidence(confidence),
            'probabilities': {
                'ham': float(1 - confidence if prediction == 'smishing' else confidence),
                'smishing': float(confidence if prediction == 'smishing' else 1 - confidence)
            },
            'model_used': model_used,
            'url_override': has_harmful_urls
        }
