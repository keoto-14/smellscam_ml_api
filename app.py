# app.py
import os
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

app = Flask(__name__)
CORS(app)

# Load ML models
models = load_models()

@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "SmellScam ML API (Flask) is running!"})

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        feats = extract_all_features(url)
        result = predict_from_features(feats, models, raw_url=url)
        return jsonify({
            "url": url,
            "features": feats,
            "result": result,
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/simple", methods=["POST"])
def simple():
    try:
        url = request.data.decode("utf-8").strip()
        if not url:
            return jsonify({"error": "Missing URL in body"}), 400

        feats = extract_all_features(url)
        result = predict_from_features(feats, models, raw_url=url)
        return jsonify({"url": url, "result": result})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/debug", methods=["GET"])
def debug():
    try:
        url = (request.args.get("url") or "").strip()
        if not url:
            return jsonify({"error": "Missing 'url' parameter"}), 400

        feats = extract_all_features(url)
        result = predict_from_features(feats, models, raw_url=url)

        return jsonify({
            "url": url,
            "features_extracted": feats,
            "predictor_output": result
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
