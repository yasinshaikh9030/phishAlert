from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
from feature_extraction import extract_features

app = Flask(__name__)
CORS(app)
# Load the model
model = joblib.load("models/phishingModel.pkl")


@app.route("/")
def home():
    return "Welcome to the Phishing Detection API.. model is loaded and ready to use"
@app.route("/predict", methods=["POST","GET"])
def predict():
    try:
        sample = [[
        -1, 1,1,1,1,-1,1,-1,-1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,-1,1,1,1,1,1,1
        ]]

        proba = model.predict_proba(sample)
        result = model.predict(sample)

        phishing_prob = proba[0][1]
        risk_percent = round(phishing_prob * 100, 2)

        if phishing_prob >= 0.85:
            status = "danger"
            message = "High Risk Phishing"
        elif phishing_prob >= 0.5:
            status = "warning"
            message = "Suspicious Website"
        else:
            status = "safe"
            message = "Website Looks Safe"

        return jsonify({
            "prediction": int(result[0]),
            "probability": float(phishing_prob),
            "risk_percent": risk_percent,
            "status": status,
            "message": message
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/predict_url", methods=["POST"])
def predict_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "No URL provided"}), 400
        
        url = data['url']
        features = extract_features(url)
        
        if len(features) != 30: # input features must be 30
            return jsonify({"error": "Feature extraction failed"}), 500
            
        sample = [features]
        proba = model.predict_proba(sample)
        result = model.predict(sample)
    
    # proba[0][1] is for legitimate 
        # The classes are likely [-1, 1]. So proba[0][0] is the probability of -1 (phishing).
        # We want the higher the phishing probability, the more dangerous it is.
        phishing_prob = proba[0][0]
        risk_percent = round(phishing_prob * 100, 2)
        print(phishing_prob)

        if phishing_prob >= 0.85:
            status = "danger"
            message = "High Risk of Phishing"
        elif phishing_prob >= 0.5:
            status = "warning"
            message = "Suspicious Website"
        else:
            status = "safe"
            message = "Website Looks Safe"

        return jsonify({
            "url": url,
            "prediction": int(result[0]),
            "probability": float(phishing_prob),
            "risk_percent": risk_percent,
            "status": status,
            "message": message
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
