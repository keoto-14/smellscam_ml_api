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

# --------------------------------------------------
# Load predictor once at startup
# --------------------------------------------------
_predictor = Predictor()
try:
    _predictor.load_models()
    logger.info("Models preloaded successfully.")
except Exception as e:
    logger.exception("Failed to preload models on startup")


# --------------------------------------------------
# Health check route
# --------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "message": "SmellScam ML API Running",
        "version": "flask-1.0"
    })


# --------------------------------------------------
# Main prediction endpoint
# --------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    """
    Accepts:
    {
        "url": "<target_url>"
    }
    """
    # Parse JSON safely
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"detail": "Invalid JSON body"}), 400

    if not isinstance(body, dict):
        return jsonify({"detail": "Invalid JSON body"}), 400

    # Get URL field
    url = body.get("url") or body.get("raw_url") or body.get("target")
    if not url:
        return jsonify({"detail": "Missing 'url' field"}), 400

    try:
        # ----------------------------------------
        # FIXED: direct call - NOT ASYNC
        # ----------------------------------------
        result = _predictor.predict_url(url)

        # Return ML prediction result
        return jsonify(result)

    except ModelLoadError as e:
        logger.exception("Model load error during prediction")
        return jsonify({"detail": str(e)}), 500

    except Exception as e:
        logger.exception("Unhandled error in /predict")
        traceback.print_exc()
        return jsonify({
            "detail": "prediction failed",
            "error": str(e)
        }), 500


# --------------------------------------------------
# Run locally (not used on Railway)
# --------------------------------------------------
if __name__ == "__main__":
    import os
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        debug=True
    )
