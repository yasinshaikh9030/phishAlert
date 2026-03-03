
🛡️ **PhishAlert** – Chrome Extension for Phishing Detection
PhishAlert is a Chrome Extension that detects whether a website is safe, suspicious, or phishing using a Machine Learning model trained on a phishing dataset.
It analyzes the current website URL in real-time and shows an automatic popup warning if the site is risky.

📌 **Features**
Real-time phishing detection
Probability-based risk levels
Auto popup warning
Automatic feature extraction
No external hosting required
Runs locally using Flask

Model Used: **Logistic Regression **— selected because the dataset features are mostly independent and linearly separable, making it fast, interpretable, 
and highly effective for binary phishing classification.

📊 Dataset
Source: Kaggle Phishing Website Dataset
Link: https://www.kaggle.com/datasets/akashkr/phishing-website-dataset
Total Features: 30+ phishing detection indicators
Target: Safe (-1) or Phishing (1)

🚀 Tech Stack
🔹 Backend
Python
Flask
joblib
flask-cors

🔹 ML & Data
numpy
pandas
matplotlib
seaborn
scikit-learn
GridSearchCV for hyperparameter tunning 

🔹 Feature Extraction Libraries
requests
BeautifulSoup (bs4)
python-whois
dnspython
ssl
socket
ipaddress
urllib
tldextract
googlesearch-python
selenium

🔹 Frontend
React
Tailwind CSS
Chrome Extension (Manifest V3)

⚙️ Project Workflow
User opens any website
Extension automatically captures the current URL
URL is sent to Flask backend
Backend extracts 30 phishing features
Model predicts phishing probability
Popup appears automatically with:
🔴 High Risk
🟡 Suspicious
🟢 Safe

🧠 How Data is Collected Automatically
The backend dynamically extracts features from the live website using:
URL structure analysis
HTML scraping
WHOIS domain lookup
DNS record checks
SSL certificate validation
Google indexing check

All features are converted into ML-compatible numeric values before prediction.

🏗️ How the Chrome Extension Was Created
Built frontend using React + Tailwind
Modified vite.config.js to output a single JS file
Created manifest.json (Manifest V3)
Configured content scripts to inject into all websites
Built optimized extension using: npm run build

Final extension generated inside: frontend/dist

📂 Project Setup
1️⃣ Create Virtual Environment
python -m venv venv
venv\Scripts\activate
2️⃣ Install Dependencies
pip install -r requirements.txt
3️⃣ Run Backend
cd backend
python app.py

Backend runs on:
http://127.0.0.1:5000

🧩 Load Extension in Chrome
Open Chrome
Go to chrome://extensions/
Enable Developer Mode
Click Load Unpacked
Select: frontend/dist
Extension will now run on all websites.
