# app.py
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import logging
import traceback

load_dotenv()

from predictor import Predictor, ModelLoadError

app = Flask("smellscam_ml_api")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smellscam.app")

_predictor = Predictor()
try:
    _predictor.load_models()
except Exception as e:
    logger.exception("Failed to preload models (startup).")

@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "SmellScam ML API Running", "version": "flask-1.0"})

@app.route("/predict", methods=["POST"])
def predict():
    """
    Accepts JSON body: { "url": "<target url>" }
    Uses request.get_json(force=True) to avoid 415 errors when client doesn't set Content-Type properly.
    """
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
        result = _predictor.predict_url(url)
        # predictor returns a dict / pydantic-like serializable structure
        return jsonify(result)
    except ModelLoadError as e:
        logger.exception("Model load error")
        return jsonify({"detail": str(e)}), 500
    except Exception as e:
        logger.exception("Unhandled error in /predict")
        traceback.print_exc()
        return jsonify({"detail": "prediction failed", "error": str(e)}), 500

if __name__ == "__main__":
    # development server (not for production)
    app.run(host="0.0.0.0", port=int(__import__("os").environ.get("PORT", 8080)))
