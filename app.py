# app.py
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import logging
import traceback
import os

load_dotenv()

from predictor import Predictor, ModelLoadError

app = Flask("smellscam_ml_api")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smellscam.app")

# Create predictor once
_predictor = Predictor()

# Load models immediately at import time
# This works in Flask 3.x and Railway
try:
    _predictor.load_models()
    logger.info("Models loaded at startup.")
except Exception as e:
    logger.exception("Failed to preload models")

@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "SmellScam ML API Running", "version": "flask-1.0"})

@app.route("/predict", methods=["POST"])
def predict():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"detail": "Invalid JSON body"}), 400

    if not isinstance(body, dict):
        return jsonify({"detail": "Invalid JSON body"}), 400

    url = body.get("url") or body.get("raw_url") or body.get("target")
    if not url:
        return jsonify({"detail": "Missing 'url' field"}), 400

    try:
        output = _predictor.predict_url(url)
        return jsonify(output)
    except ModelLoadError as e:
        logger.exception("Model load error")
        return jsonify({"detail": str(e)}), 500
    except Exception as e:
        logger.exception("Prediction failed")
        traceback.print_exc()
        return jsonify({"detail": "prediction failed", "error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
