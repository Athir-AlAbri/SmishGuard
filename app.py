from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
import torch
import re
import numpy as np
import requests
import time
from urllib.parse import urlparse
from lime.lime_text import LimeTextExplainer
import warnings
from deep_translator import GoogleTranslator
import os
from dotenv import load_dotenv

warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

load_dotenv()

# VirusTotal API Configuration - now from environment variables
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{}"

# Validate API key is loaded
if not VIRUSTOTAL_API_KEY:
    print("\n" + "="*60)
    print("⚠️  WARNING: VIRUSTOTAL_API_KEY not found!")
    print("   Please create a .env file with your API key")
    print("   Example: VIRUSTOTAL_API_KEY=your_key_here")
    print("="*60 + "\n")
else:
    print(f"✅ VirusTotal API Key loaded successfully: {VIRUSTOTAL_API_KEY[:10]}...")


class MessageTranslator:
    def __init__(self):
        self.translator = GoogleTranslator(source='auto', target='en')
    
    def detect_language(self, text):
        """Detect if text is Arabic or English"""
        arabic_pattern = re.compile(r'[\u0600-\u06FF]')
        has_arabic = bool(arabic_pattern.search(text))
        return 'ar' if has_arabic else 'en'
    
    def translate(self, text, source_lang='ar', target_lang='en'):
        if source_lang == 'en':
            return {
                'original': text,
                'translated': text,
                'source_lang': 'en',
                'needs_translation': False
            }
        
        try:
            translated_text = GoogleTranslator(source='ar', target='en').translate(text)
            
            return {
                'original': text,
                'translated': translated_text,
                'source_lang': source_lang,
                'needs_translation': True
            }
        except Exception as e:
            print(f"Translation error: {e}")
            return None

class VirusTotalChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
    
    def extract_urls(self, text):
        """Extract all URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls
    
    def check_url(self, url):
        """Check a single URL using VirusTotal API"""
        try:
            scan_response = requests.post(
                VIRUSTOTAL_URL_SCAN,
                headers=self.headers,
                data={"url": url},
                timeout=10
            )
            
            if scan_response.status_code != 200:
                return {
                    'error': f'VirusTotal API error: {scan_response.status_code}',
                    'url': url
                }
            
            scan_data = scan_response.json()
            url_id = scan_data['data']['id']
            
            max_retries = 5
            retry_delay = 3
            
            for attempt in range(max_retries):
                time.sleep(retry_delay)
                report_url = VIRUSTOTAL_URL_REPORT.format(url_id)
                report_response = requests.get(report_url, headers=self.headers, timeout=10)
                
                if report_response.status_code == 400:
                    if attempt < max_retries - 1:
                        continue
                    else:
                        return self.get_cached_report(url)
                
                if report_response.status_code != 200:
                    if attempt < max_retries - 1:
                        continue
                    return {'error': f'Could not retrieve report', 'url': url}
                
                report_data = report_response.json()
                stats = report_data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_engines = sum(stats.values())
                is_harmful = malicious > 0 or suspicious > 0
                
                return {
                    'url': url,
                    'is_harmful': is_harmful,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'total_engines': total_engines,
                    'status': 'HARMFUL' if is_harmful else 'SAFE',
                    'details': f"{malicious} engines flagged as malicious, {suspicious} as suspicious"
                }
        except Exception as e:
            return {'error': f'Error checking URL: {str(e)}', 'url': url}
    
    def get_cached_report(self, url):
        """Try to get cached report"""
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            report_response = requests.get(report_url, headers=self.headers, timeout=10)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                stats = report_data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                is_harmful = malicious > 0 or suspicious > 0
                
                return {
                    'url': url,
                    'is_harmful': is_harmful,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'status': 'HARMFUL' if is_harmful else 'SAFE',
                    'cached': True
                }
        except:
            pass
        return {'error': 'Analysis in progress', 'url': url}


class SmishingDetector:
    """
    Pure ML-based smishing detection with LIME explainability
    """
    
    # Minimum word length for LIME highlighting (filters noise from short words)
    MIN_WORD_LENGTH = 3
    
    def __init__(self):
        try:
            self.model_path = "distilbert-smishing-final"
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.classifier = pipeline("text-classification", model=self.model, tokenizer=self.tokenizer, device=-1)
            self.lime_explainer = LimeTextExplainer(class_names=['ham', 'smishing'], split_expression=r'\W+', bow=False)
            print("Fine-tuned DistilBERT model loaded successfully!")
            self.model_loaded = True
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model_loaded = False
            self.classifier = None
    
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
    
    def get_lime_explanation(self, text, final_prediction, num_features=15):
       
        if not self.model_loaded or self.lime_explainer is None:
            return None
        
        try:
            print(f" Generating LIME explanation for: {final_prediction.upper()}")
            
            # Force LIME to explain both classes by increasing num_samples
            exp = self.lime_explainer.explain_instance(
                text, 
                self.predict_proba_for_lime, 
                num_features=num_features,
                num_samples=1000,  # Increased for better coverage
                labels=(0, 1)  # CRITICAL: Force explanation for both classes
            )
            
            # Map prediction to correct class index
            # Class 0 = HAM, Class 1 = SMISHING
            predicted_class_index = 1 if final_prediction.lower() == 'smishing' else 0
            
            # Verify the class exists in explanation
            available_classes = list(exp.local_exp.keys())
            print(f"📋 Available classes in explanation: {available_classes}")
            
            if predicted_class_index not in exp.local_exp:
                print(f"⚠️ Warning: Class {predicted_class_index} not found. Using fallback.")
                # If the desired class isn't available, we have a problem
                # This shouldn't happen with labels=(0,1), but handle it anyway
                if len(available_classes) > 0:
                    predicted_class_index = available_classes[0]
                else:
                    raise ValueError("No labels available in LIME explanation")
            
            class_name = 'SMISHING' if predicted_class_index == 1 else 'HAM'
            print(f"📊 Explaining class index {predicted_class_index} ({class_name})")
            
            # Get explanation for predicted class only
            explanation = exp.as_list(label=predicted_class_index)
            
            # Store weights for the predicted class only
            predicted_weights = {}
            
            for feature, weight in explanation:
                cleaned_feature = feature.strip('<>=').lower()
                
                # Filter short words
                if len(cleaned_feature) < self.MIN_WORD_LENGTH:
                    continue
                
                # Only keep positive weights (words that support the prediction)
                if weight > 0:
                    predicted_weights[cleaned_feature] = float(weight)
            
            # Calculate max weight for normalization
            max_weight = max(predicted_weights.values()) if predicted_weights else 1
            
            print(f"✅ Extracted {len(predicted_weights)} supporting words (max weight: {max_weight:.4f})")
            
            return {
                'predicted_class': final_prediction,
                'predicted_weights': predicted_weights,
                'max_weight': max_weight,
                'explanation_available': True,
                'min_word_length': self.MIN_WORD_LENGTH
            }
            
        except Exception as e:
            print(f" LIME error: {e}")
            import traceback
            traceback.print_exc()
            return {'explanation_available': False, 'error': str(e)}


    def predict_proba_for_lime(self, texts):
        """Prediction function for LIME - returns [ham_prob, smishing_prob]"""
        if not self.model_loaded:
            return np.array([[0.5, 0.5]] * len(texts))
        
        results = []
        for text in texts:
            try:
                output = self.classifier(text)[0]
                label = output['label']
                confidence = output['score']
                
                # Determine probabilities for both classes
                # CRITICAL: Ensure consistent mapping
                # Index 0 = HAM probability
                # Index 1 = SMISHING probability
                if label.lower() in ['smish', 'smishing', '1', 'label_1']:
                    ham_prob = 1 - confidence
                    smishing_prob = confidence
                else:
                    ham_prob = confidence
                    smishing_prob = 1 - confidence
                
                # Return as [ham_prob, smishing_prob]
                results.append([ham_prob, smishing_prob])
                
            except Exception as e:
                print(f"Error in LIME prediction: {e}")
                results.append([0.5, 0.5])
        
        return np.array(results)
        
    def predict(self, text, include_lime=True, url_scan_results=None):
        """
        Main prediction method - pure model-based
        """
        if not self.model_loaded:
            return self.fallback_predict(text, url_scan_results)
        
        try:
            # Get AI model prediction
            result = self.classifier(text)[0]
            label = result['label']
            confidence = result['score']
            
            # Determine prediction class
            if label.lower() in ['smish', 'smishing', '1', 'label_1']:
                prediction = 'smishing'
                smishing_prob = confidence
                ham_prob = 1 - confidence
            else:
                prediction = 'ham'
                ham_prob = confidence
                smishing_prob = 1 - confidence
            
            confidence_level = self.categorize_confidence(confidence)
            
            # Log prediction
            print("\n" + "="*60)
            print(" MODEL PREDICTION")
            print("="*60)
            print(f"Model Label: {label}")
            print(f"Prediction: {prediction.upper()}")
            print(f"Confidence: {confidence:.3f} ({confidence_level})")
            print(f"Probabilities: HAM={ham_prob:.3f}, SMISHING={smishing_prob:.3f}")
            print("="*60 + "\n")
            
            # Build response
            response = {
                'prediction': prediction,
                'confidence': float(confidence),
                'confidence_level': confidence_level,
                'probabilities': {
                    'ham': float(ham_prob),
                    'smishing': float(smishing_prob)
                },
                'model_label': label,
                'model_used': 'Fine-tuned DistilBERT'
            }
            
            # Add LIME explanation if requested
            if include_lime:
                print("🔬 Generating LIME explanation...")
                lime_result = self.get_lime_explanation(text, prediction)
                if lime_result and lime_result.get('explanation_available'):
                    response['lime_explanation'] = lime_result
                    print("LIME explanation added to response")
                else:
                    print("LIME explanation not available")
            
            return response
            
        except Exception as e:
            print(f" Prediction error: {e}")
            import traceback
            traceback.print_exc()
            return self.fallback_predict(text, url_scan_results)
    
    def fallback_predict(self, text, url_scan_results=None):
        """
        Fallback prediction when model is unavailable
        """
        # Check for harmful URLs
        has_harmful_url = False
        if url_scan_results:
            harmful_urls = [r for r in url_scan_results if r.get('is_harmful', False)]
            has_harmful_url = len(harmful_urls) > 0
        
        # Simple heuristic
        if has_harmful_url:
            prediction = 'smishing'
            confidence = 0.85
        else:
            # Basic keyword check
            text_lower = text.lower()
            suspicious_keywords = ['urgent', 'verify', 'suspended', 'click', 'confirm', 'immediately']
            keyword_count = sum(1 for kw in suspicious_keywords if kw in text_lower)
            
            if keyword_count >= 3:
                prediction = 'smishing'
                confidence = 0.70
            else:
                prediction = 'ham'
                confidence = 0.60
        
        return {
            'prediction': prediction,
            'confidence': float(confidence),
            'confidence_level': self.categorize_confidence(confidence),
            'probabilities': {
                'ham': float(1 - confidence if prediction == 'smishing' else confidence),
                'smishing': float(confidence if prediction == 'smishing' else 1 - confidence)
            },
            'model_used': 'Rule-based Fallback'
        }


# Initialize components
detector = SmishingDetector()
vt_checker = VirusTotalChecker(VIRUSTOTAL_API_KEY)
translator = MessageTranslator()

# Flask Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/learn')
def learn():
    return render_template('learn.html')

@app.route('/analyze', methods=['POST'])
def analyze_message():
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        is_production = os.environ.get('RENDER', False)
        include_lime = data.get('include_lime', True) and not is_production
        
        if not message or len(message) < 5:
            return jsonify({'error': 'Invalid message'}), 400
        
        print("\n" + "="*60)
        print(" NEW MESSAGE ANALYSIS")
        print("="*60)
        print(f"Message: {message}")
        
        # Language detection and translation
        detected_lang = translator.detect_language(message)
        translation_result = None
        analysis_text = message
        
        if detected_lang == 'ar':
            translation_result = translator.translate(message)
            if translation_result:
                analysis_text = translation_result['translated']
        
        # URL scanning
        urls = vt_checker.extract_urls(message)
        url_results = []
        if urls:
            for url in urls:
                result = vt_checker.check_url(url)
                url_results.append(result)
        
        # AI analysis (pure model-based)
        analysis = detector.predict(analysis_text, include_lime=include_lime, url_scan_results=url_results)
        
        # Add URL results
        analysis['url_scan_results'] = url_results
        analysis['urls_found'] = len(urls)
        
        # Add translation (simplified - no word mapping)
        if translation_result:
            analysis['translation'] = translation_result
        
        print(f"Final Prediction: {analysis['prediction'].upper()}")
        print(f"Confidence: {analysis['confidence']:.3f} ({analysis['confidence_level']})")
        print("="*60 + "\n")
        
        return jsonify(analysis)
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Analysis failed'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': detector.model_loaded,
        'min_word_length_filter': detector.MIN_WORD_LENGTH
    })

if __name__ == '__main__':
    print("Starting SmishGuard System")
    app.run(debug=True, host='0.0.0.0', port=5000)
