# 🛡️ Phishing Website Detection

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.2.2-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

## 🌟 Overview

A powerful browser extension and web application that helps protect users from phishing websites by analyzing URLs and website content in real-time. This project combines machine learning with web security to provide an extra layer of protection against malicious websites.

## ✨ Features

- 🔍 Real-time URL analysis
- 🤖 Machine learning-based phishing detection
- 🛡️ Browser extension integration
- 📊 Detailed threat analysis
- 🚀 Fast and efficient processing
- 🔒 Privacy-focused design

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, or Edge)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/phoenixdev100/phishing-website-detection.git
cd phishing-website-detection
```

2. Create and activate a virtual environment:
```bash
# On Windows
python -m venv venv
.\venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies with specific versions to avoid compatibility issues:
```bash
pip install Flask==2.2.2
pip install Werkzeug==2.2.2
pip install -r requirements.txt
```

## 🚀 Usage

1. Start the Flask server:
```bash
# Make sure you're in the virtual environment
python app.py
```

2. The browser extension will automatically analyze websites you visit and display warnings for potential phishing attempts.

### Troubleshooting

If you encounter the error `ImportError: cannot import name 'url_quote' from 'werkzeug.urls'`, try these steps:

1. Deactivate and reactivate your virtual environment:
```bash
deactivate
.\venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On macOS/Linux
```

2. Reinstall the dependencies with specific versions:
```bash
pip uninstall Flask Werkzeug
pip install Flask==2.2.2 Werkzeug==2.2.2
```
3. Open your browser and navigate to:
```
http://localhost:5000
```

## 🧠 How It Works

The system uses multiple features to detect phishing websites:

- URL analysis
- Domain age and registration details
- Website content analysis
- Machine learning model predictions
- SSL certificate verification

## 📁 Project Structure

```
phishing-website-detection/
├── app.py                 # Flask application
├── background.js          # Extension background script
├── popup.html            # Extension popup interface
├── popup.js              # Popup functionality
├── manifest.json         # Extension configuration
├── train_model.py        # Model training script
├── phishing_model.pkl    # Trained model
└── requirements.txt      # Python dependencies
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve this project
- Special thanks to the open-source community for their valuable tools and libraries

---

<div align="center">
  
Made with ❤️ by **Deepak**
</div>

<style>
  /* Add some beautiful styling */
  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
  }
  
  h1, h2, h3 {
    color: #2c3e50;
    margin-top: 1.5em;
  }
  
  code {
    background-color: #f8f9fa;
    padding: 2px 4px;
    border-radius: 4px;
    font-family: 'Courier New', Courier, monospace;
  }
  
  pre {
    background-color: #f8f9fa;
    padding: 15px;
    border-radius: 6px;
    overflow-x: auto;
  }
  
  a {
    color: #3498db;
    text-decoration: none;
  }
  
  a:hover {
    text-decoration: underline;
  }
</style> 