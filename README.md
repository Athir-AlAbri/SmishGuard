# SmishGuard 🛡️

AI-powered SMS phishing (smishing) detection system using fine-tuned DistilBERT and Flask.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)

## 🚀 Features

- 🤖 **Fine-tuned DistilBERT Model** - Pure ML-based smishing detection
- 📊 **Confidence Scoring** - Four-tier classification (Very High/High/Medium/Low)
- 🔍 **VirusTotal Integration** - Automatic URL scanning for malicious links
- 🌐 **Arabic Support** - Automatic translation for Arabic SMS messages
- 💡 **Explainable AI** - LIME visualization highlighting influential words
- 🎓 **Interactive Quiz** - Test your skills with 3 difficulty levels
- 🛡️ **Action Guidance** - Context-specific security recommendations
- 🔤 **Smart Word Filtering** - Filters noise by highlighting words ≥3 characters

## 📋 Technology Stack

- **Backend:** Flask (Python 3.8+)
- **ML Model:** DistilBERT (Hugging Face Transformers)
- **Explainability:** LIME (Local Interpretable Model-agnostic Explanations)
- **APIs:** VirusTotal v3, Google Translator
- **Frontend:** HTML5, CSS3, Vanilla JavaScript

## 🔧 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- 4GB RAM minimum (8GB recommended)
- Internet connection (for API calls)

### Setup Steps

1. **Clone the repository**
```bash
git clone https://github.com/Athir-AlAbri/SmishGuard.git
cd SmishGuard
```

2. **Create virtual environment (recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install flask flask-cors transformers torch numpy requests lime deep-translator python-dotenv
```

4. **Configure environment variables**
```bash
cp .env.example .env
```

Edit `.env` and add your VirusTotal API key:
```bash
VIRUSTOTAL_API_KEY=your-api-key-here
FLASK_ENV=development
FLASK_DEBUG=True
```

Get a free API key at: [VirusTotal](https://www.virustotal.com/gui/join-us)

5. **Ensure model files are present**

The fine-tuned DistilBERT model should be in:
```
distilbert-smishing-final/
├── config.json
├── pytorch_model.bin
├── tokenizer_config.json
├── vocab.txt
└── special_tokens_map.json
```

> **Note:** If model files are missing, the system will fall back to rule-based detection.

6. **Run the application**
```bash
python app.py
```

You should see:
```
✅ VirusTotal API Key loaded successfully
✅ Fine-tuned DistilBERT model loaded successfully!
🚀 Starting SmishGuard System
 * Running on http://0.0.0.0:5000
```

7. **Open your browser**
```
http://localhost:5000
```

## 📁 Project Structure
```
SmishGuard/
├── app.py                          # Main Flask application
├── .env.example                    # Environment variables template
├── .env                            # Your API keys (gitignored)
├── .gitignore                      # Git ignore rules
├── requirements.txt                # Python dependencies
├── distilbert-smishing-final/      # Fine-tuned ML model
│   ├── config.json
│   ├── pytorch_model.bin
│   └── ...
├── templates/                      # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── analysis.html
│   ├── quiz.html
│   └── learn.html
└── static/                         # CSS and JavaScript
    ├── style.css
    └── script.js
```

## 🎯 Usage

### 1. Home Page
System overview, features, and statistics

### 2. AI Analysis
- Paste any SMS message (English or Arabic)
- Get instant classification (Ham/Smishing)
- View confidence level (Very High/High/Medium/Low)
- See LIME explanation with highlighted words
- Check URL scanning results
- Get action recommendations

### 3. Interactive Quiz
- 3 difficulty levels: Beginner, Intermediate, Expert
- 5 questions per level
- Immediate feedback with explanations
- Learn to identify smishing patterns

### 4. Learn
Educational resources about smishing threats and protection tips

## 🧠 Model Information

- **Base Model:** DistilBERT (distilbert-base-uncased)
- **Task:** Binary sequence classification
- **Classes:** Ham (legitimate) vs Smishing (malicious)
- **Training:** Fine-tuned on SMS phishing dataset
- **Device:** CPU (default), GPU-compatible

### Confidence Levels

| Level | Confidence Range | Description |
|-------|-----------------|-------------|
| 🔴 **VERY HIGH** | ≥ 0.90 | Extremely confident prediction |
| 🟠 **HIGH** | 0.75 - 0.89 | High confidence prediction |
| 🟡 **MEDIUM** | 0.60 - 0.74 | Moderate confidence |
| 🟢 **LOW** | < 0.60 | Lower confidence |

### LIME Explainability

- Highlights words that influenced the AI's decision
- **Filters words < 3 characters** to reduce noise
- Shows only positive supporting evidence
- Color intensity indicates word importance
- Works for both English and Arabic (translated) messages

## 📊 API Endpoints

### POST /analyze

Analyze SMS message for smishing patterns.

**Request:**
```json
{
  "message": "Your SMS text here",
  "include_lime": true
}
```

**Response:**
```json
{
  "prediction": "smishing",
  "confidence": 0.92,
  "confidence_level": "VERY HIGH",
  "probabilities": {
    "ham": 0.08,
    "smishing": 0.92
  },
  "model_label": "LABEL_1",
  "model_used": "Fine-tuned DistilBERT",
  "lime_explanation": {
    "predicted_class": "smishing",
    "predicted_weights": {
      "urgent": 0.15,
      "verify": 0.12,
      "account": 0.10
    },
    "max_weight": 0.15,
    "explanation_available": true,
    "min_word_length": 3
  },
  "url_scan_results": [],
  "urls_found": 0,
  "translation": null
}
```

### GET /health

Check system health and model status.

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "min_word_length_filter": 3
}
```

## 🔍 Detection Features

### Pure ML-Based Detection
The system relies primarily on the fine-tuned DistilBERT model for classification, with fallback to rule-based detection if the model is unavailable.

**Fallback Detection (when model unavailable):**
1. **Harmful URLs** - VirusTotal-flagged malicious links
2. **Suspicious Keywords** - "urgent", "verify", "suspended", etc.
3. **Keyword Density** - Multiple suspicious terms

## 🛡️ Security

⚠️ **Never commit sensitive credentials!**

- The `.env` file is automatically ignored by Git
- Use `.env.example` as a template
- Never share your VirusTotal API key
- Rotate keys if accidentally exposed

**API Key Validation:**
The app will warn you if the API key is missing:
```
⚠️  WARNING: VIRUSTOTAL_API_KEY not found!
   Please create a .env file with your API key
```

## 🌐 Multilingual Support

- **English:** Native analysis
- **Arabic:** Automatic translation to English for analysis
- **Detection:** Identifies Arabic text using Unicode patterns
- **LIME:** Shows explanations for translated text

## 🐛 Troubleshooting

### Model Not Found Error
```
Error loading model: [Errno 2] No such file or directory
```
**Solution:** Ensure `distilbert-smishing-final/` folder is present with all model files.

### VirusTotal API Error
```
VirusTotal API error: 403
```
**Solution:** Check your `.env` file has the correct API key. Free tier has 4 requests/minute limit.

### Translation Fails
**Solution:** Ensure internet connection. System will analyze in original language if translation fails.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Athir Al-Abri**
- GitHub: [@Athir-AlAbri](https://github.com/Athir-AlAbri)

## 🙏 Acknowledgments

- Hugging Face for Transformers library
- VirusTotal for URL scanning API
- LIME for explainable AI framework
- Google Translator for multilingual support

---

**⚠️ Disclaimer:** This tool is for educational and research purposes. Always verify suspicious messages through official channels.

echo "
## 📦 Cloning the Repository

This repository uses Git LFS for large model files. To clone:

\`\`\`bash
# Install Git LFS first
brew install git-lfs  # macOS
# or: sudo apt-get install git-lfs  # Linux

# Initialize Git LFS
git lfs install

# Clone the repository
git clone https://github.com/Athir-AlAbri/SmishGuard.git
cd SmishGuard

# Pull LFS files
git lfs pull
\`\`\`
" >> README.md

git add README.md
git commit -m "Add Git LFS installation instructions"
git push origin main
