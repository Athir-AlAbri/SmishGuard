# SmishGuard User Manual

## Table of Contents
1. [Introduction](#introduction)
2. [System Overview](#system-overview)
3. [Installation Guide](#installation-guide)
4. [Getting Started](#getting-started)
5. [Using SmishGuard](#using-smishguard)
6. [Understanding the Model](#understanding-the-model)
7. [Dataset Management](#dataset-management)
8. [Testing and Validation](#testing-and-validation)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## Introduction

### What is SmishGuard?
SmishGuard is an AI-powered SMS phishing (smishing) detection system that uses advanced machine learning techniques to identify potentially malicious text messages. Built on the DistilBERT natural language processing model and implemented with Flask, SmishGuard provides reliable protection against SMS-based phishing attacks.

### Key Features
- **AI-Powered Detection**: Uses DistilBERT transformer model for accurate smishing detection
- **Real-time Analysis**: Instant SMS message classification
- **High Accuracy**: Trained on comprehensive datasets to minimize false positives
- **User-Friendly Interface**: Flask-based web interface for easy interaction
- **Extensible**: Modular architecture for easy customization and updates

### Who Should Use This Manual?
This manual is designed for:
- End users who want to check SMS messages for phishing attempts
- Developers implementing SmishGuard in their applications
- Administrators deploying and maintaining SmishGuard systems
- Researchers working on SMS security

---

## System Overview

### Architecture
SmishGuard consists of five main components:

1. **Dataset Preprocessing Module**: Prepares and cleans training data
2. **DistilBERT Model Implementation**: Core AI model for classification
3. **DistilBERT Model Testing**: Validates DistilBERT model performance
4. **Other Models**: Additional ML models tested for comparison
5. **SmishGard Application**: Flask-based web interface

### Technology Stack
- **Machine Learning Framework**: PyTorch/TensorFlow with Transformers library
- **Model**: DistilBERT (Distilled version of BERT)
- **Web Framework**: Flask
- **Language**: Python 3.x
- **Additional Libraries**: NumPy, Pandas, Scikit-learn

### System Requirements

#### Minimum Requirements
- Python 3.7 or higher
- 4GB RAM
- 2GB free disk space
- Internet connection (for initial model download)

#### Recommended Requirements
- Python 3.9 or higher
- 8GB RAM or more
- 5GB free disk space
- GPU support (optional, for faster processing)

---

## Installation Guide

### Prerequisites
Before installing SmishGuard, ensure you have:
- Python 3.7+ installed
- pip package manager
- Virtual environment tool (recommended)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Athir-AlAbri/SmishGuard.git
cd SmishGuard
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

Common dependencies include:
- `flask`
- `transformers`
- `torch` or `tensorflow`
- `pandas`
- `numpy`
- `scikit-learn`

### Step 4: Environment Configuration
Create a `.env` file in the root directory (if not already present):
```
FLASK_APP=app.py
FLASK_ENV=development
MODEL_PATH=./models
```

### Step 5: Download Pre-trained Model
The DistilBERT model will be automatically downloaded on first run, or you can manually download it:
```bash
python download_model.py
```

### Verification
Test your installation:
```bash
python -c "import flask, transformers; print('Installation successful!')"
```

---

## Getting Started

### Quick Start Guide

#### 1. Start the Application
Navigate to the SmishGard directory:
```bash
cd SmishGard
python app.py
```

The application should start on `http://localhost:5000`

#### 2. Access the Web Interface
Open your web browser and navigate to:
```
http://localhost:5000
```

#### 3. Test a Message
Enter an SMS message in the text input field and click "Analyze" to receive a classification.

### Understanding the Interface

The SmishGuard interface typically includes:
- **Text Input Area**: Where you paste or type the SMS message
- **Analyze Button**: Triggers the classification
- **Results Panel**: Displays:
  - Classification (Legitimate/Phishing)
  - Confidence Score (0-100%)
  - Risk Level (Low/Medium/High)
  - Detailed Analysis

### Example Usage

**Example 1: Legitimate Message**
```
Input: "Your package has been delivered. Thank you for your order!"
Result: Legitimate (95% confidence)
```

**Example 2: Phishing Message**
```
Input: "URGENT! Your account will be closed. Click here immediately: http://suspicious-link.com"
Result: Phishing (98% confidence)
```

---

## Using SmishGuard

### Analyzing SMS Messages

#### Via Web Interface
1. Copy the suspicious SMS message
2. Open SmishGuard in your browser
3. Paste the message in the input field
4. Click "Analyze"
5. Review the results

#### Via API (for Developers)
SmishGuard provides a RESTful API for integration:

```python
import requests

url = "http://localhost:5000/api/analyze"
data = {
    "message": "Your SMS message here"
}

response = requests.post(url, json=data)
result = response.json()
print(f"Classification: {result['classification']}")
print(f"Confidence: {result['confidence']}%")
```

### Interpreting Results

#### Classification Types
- **Legitimate**: The message appears to be safe
- **Phishing**: The message shows signs of smishing attack
- **Suspicious**: The message contains ambiguous indicators

#### Confidence Levels
- **90-100%**: Very High Confidence
- **75-89%**: High Confidence
- **60-74%**: Moderate Confidence
- **Below 60%**: Low Confidence (manual review recommended)

#### Risk Indicators
SmishGuard identifies several phishing indicators:
- Urgent language ("Act now!", "Immediately")
- Suspicious URLs
- Requests for personal information
- Spelling and grammatical errors
- Unknown senders claiming to be known entities
- Threats or pressure tactics

### Best Practices

1. **Always Verify**: Use SmishGuard as a tool, not the sole decision-maker
2. **Check Multiple Messages**: Run similar messages for comparison
3. **Keep Updated**: Regularly update the model with new data
4. **Report False Positives**: Help improve the system by reporting errors
5. **Context Matters**: Consider the sender and your recent activities

---

## Understanding the Model

### Why DistilBERT?
SmishGuard uses DistilBERT as the primary model after evaluating multiple alternatives (see `Other Models` directory). DistilBERT was chosen because:
- 40% smaller than BERT
- 60% faster processing speed
- Retains 97% of BERT's accuracy
- Ideal for real-time applications
- Better balance of performance and efficiency

### Model Comparison
The project tested various models including traditional machine learning approaches and other transformers. Performance comparisons can be found in the `Other Models` directory, showing why DistilBERT was selected as the optimal solution.

### How It Works

1. **Text Preprocessing**: Message is tokenized and cleaned
2. **Encoding**: Text converted to numerical representations
3. **Analysis**: Model analyzes patterns and context
4. **Classification**: Output probability for legitimate vs. phishing
5. **Post-processing**: Results formatted for user display

### Model Training
The model is trained on:
- Thousands of legitimate SMS messages
- Known phishing SMS examples
- Real-world smishing attacks
- Manually verified examples

### Model Performance Metrics
- **Accuracy**: Percentage of correct predictions
- **Precision**: Reliability of phishing predictions
- **Recall**: Ability to detect all phishing attempts
- **F1 Score**: Balance between precision and recall

---

## Dataset Management

### Dataset Preprocessing

The `Datasets preprocessing for all models` directory contains scripts for preparing training data.

#### Preprocessing Steps
1. **Data Cleaning**: Remove duplicates and errors
2. **Normalization**: Standardize text format
3. **Labeling**: Ensure correct classification labels
4. **Balancing**: Equal representation of legitimate and phishing messages
5. **Splitting**: Divide into training, validation, and test sets

#### Running Preprocessing
```bash
cd "Datasets preprocessing for all models"
python preprocess.py --input raw_data.csv --output processed_data.csv
```

### Adding New Data

To improve the model with new examples:

1. **Prepare Data**: Format as CSV with columns `message` and `label`
2. **Add to Dataset**: Append to existing dataset
3. **Preprocess**: Run preprocessing scripts
4. **Retrain Model**: Use updated dataset for training

Example CSV format:
```csv
message,label
"Your package is ready for pickup",legitimate
"Click here to verify your account NOW!",phishing
```

---

## Testing and Validation

### Running Model Tests

The `DistilBERT Model Testing` directory contains test scripts for the main model:

```bash
cd "DistilBERT Model Testing"
python test_model.py
```

### Testing Other Models

The `Other Models` directory contains alternative model implementations that were evaluated:

```bash
cd "Other Models"
# Run specific model tests
python test_alternative_models.py
```

This allows comparison between DistilBERT and other approaches such as:
- Traditional ML models (SVM, Random Forest, Naive Bayes)
- Other transformer models (BERT, RoBERTa, etc.)
- Ensemble methods

### Test Types

#### Unit Tests
Test individual components:
```bash
python -m pytest tests/
```

#### Integration Tests
Test complete workflow:
```bash
python integration_test.py
```

#### Performance Tests
Evaluate speed and accuracy:
```bash
python performance_test.py
```

### Interpreting Test Results

Tests typically output:
- **Confusion Matrix**: True/False Positives and Negatives
- **ROC Curve**: True Positive Rate vs False Positive Rate
- **Accuracy Metrics**: Precision, Recall, F1 Score
- **Processing Time**: Speed benchmarks

### Validation Checklist
- [ ] Accuracy > 90%
- [ ] False Positive Rate < 5%
- [ ] False Negative Rate < 3%
- [ ] Average processing time < 1 second
- [ ] All unit tests pass

---

## Troubleshooting

### Common Issues

#### Issue: Application Won't Start
**Symptoms**: Error when running `python app.py`

**Solutions**:
- Verify Python version: `python --version`
- Check dependencies: `pip list`
- Review error messages in console
- Ensure port 5000 is available
- Check `.env` file configuration

#### Issue: Low Accuracy
**Symptoms**: Many incorrect classifications

**Solutions**:
- Update to latest model version
- Retrain with more recent data
- Check dataset balance
- Verify preprocessing steps
- Clear model cache

#### Issue: Slow Performance
**Symptoms**: Long wait times for results

**Solutions**:
- Enable GPU acceleration if available
- Reduce batch size in configuration
- Close unnecessary applications
- Check system resource usage
- Consider using DistilBERT instead of full BERT

#### Issue: Import Errors
**Symptoms**: `ModuleNotFoundError`

**Solutions**:
```bash
pip install --upgrade -r requirements.txt
```

#### Issue: Model Download Fails
**Symptoms**: Cannot download DistilBERT model

**Solutions**:
- Check internet connection
- Verify firewall settings
- Manually download from Hugging Face Hub
- Use offline mode with local model

### Debug Mode

Enable debug mode for detailed logs:
```bash
export FLASK_ENV=development
python app.py
```

Or in `.env`:
```
FLASK_DEBUG=1
```

### Getting Help

If issues persist:
1. Check the GitHub Issues page
2. Review documentation and logs
3. Contact the development team
4. Submit bug reports with:
   - System specifications
   - Error messages
   - Steps to reproduce
   - Screenshots (if applicable)

---

## FAQ

### General Questions

**Q: What is smishing?**
A: Smishing (SMS phishing) is a cyberattack where fraudsters use text messages to trick victims into revealing personal information, clicking malicious links, or transferring money.

**Q: How accurate is SmishGuard?**
A: SmishGuard typically achieves 90-95% accuracy on test datasets, though performance may vary based on the specific types of messages.

**Q: Does SmishGuard require internet access?**
A: Initial setup requires internet to download the model. After that, it can run offline for message analysis.

**Q: Can I use SmishGuard on mobile devices?**
A: SmishGuard is primarily designed for desktop/server deployment, but the API can be accessed from mobile browsers or apps.

### Technical Questions

**Q: Can I integrate SmishGuard into my app?**
A: Yes, SmishGuard provides a REST API for easy integration into other applications.

**Q: How often should I retrain the model?**
A: Recommended every 3-6 months or when new phishing patterns emerge.

**Q: What languages does SmishGuard support?**
A: Currently optimized for English. Support for other languages depends on training data availability.

**Q: Can I customize the classification threshold?**
A: Yes, you can adjust confidence thresholds in the configuration file.

### Privacy and Security

**Q: Does SmishGuard store my messages?**
A: By default, messages are not stored. Check your configuration and local deployment settings.

**Q: Is my data secure?**
A: When self-hosted, you have complete control over data security. Follow best practices for server security.

**Q: Can SmishGuard detect all phishing attempts?**
A: No system is 100% accurate. SmishGuard significantly reduces risk but should be used alongside other security measures.

### Maintenance

**Q: How do I update SmishGuard?**
A: Pull the latest changes from GitHub and reinstall dependencies:
```bash
git pull origin main
pip install --upgrade -r requirements.txt
```

**Q: What are the ongoing maintenance requirements?**
A: Regular updates, monitoring performance metrics, and periodic retraining with new data.

---

## Additional Resources

### Documentation
- [GitHub Repository](https://github.com/Athir-AlAbri/SmishGuard)
- [DistilBERT Documentation](https://huggingface.co/distilbert-base-uncased)
- [Flask Documentation](https://flask.palletsprojects.com/)

### Community
- Report Issues: GitHub Issues
- Contribute: Pull Requests welcome
- Discussions: GitHub Discussions

### Citation
If you use SmishGuard in research, please cite:
```
SmishGuard: AI-Powered SMS Phishing Detection
Athir AlAbri
GitHub: https://github.com/Athir-AlAbri/SmishGuard
```

---

## Appendix

### Glossary
- **Smishing**: SMS-based phishing attack
- **DistilBERT**: Distilled Bidirectional Encoder Representations from Transformers
- **NLP**: Natural Language Processing
- **Classification**: Categorizing text as legitimate or phishing
- **Confidence Score**: Model's certainty in its prediction
- **False Positive**: Legitimate message incorrectly marked as phishing
- **False Negative**: Phishing message incorrectly marked as legitimate

### Version History
- v1.0: Initial release with DistilBERT implementation
- Check GitHub releases for latest updates

### License
Please refer to the LICENSE file in the repository for usage terms.

### Contact
For questions or support:
- GitHub: [@Athir-AlAbri](https://github.com/Athir-AlAbri)
- Issues: [Submit an Issue](https://github.com/Athir-AlAbri/SmishGuard/issues)

---

*Last Updated: December 2025*
*SmishGuard User Manual v1.0*