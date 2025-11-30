import os
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import mysql.connector

# Load environment variables (.env)
load_dotenv()

# ML modules
from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

# --------------------------------------------------
# Flask App Init (Same Style as Your Old Version)
# --------------------------------------------------
app = Flask(__name__)
CORS(app)

# Load ML models once
models = load_models()

# --------------------------------------------------
# Database Helper (same style)
# --------------------------------------------------
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        autocommit=True
    )


# --------------------------------------------------
# Root Route (same as original)
# --------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "running",
        "service": "SmellScam ML API",
        "fast_mode": os.getenv("FAST_MODE", "0")
    })


# --------------------------------------------------
# /predict (OLD STYLE + FIXED)
# --------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Must force JSON only → prevents 415 issues
        data = request.get_json(force=True, silent=False)

        if not data:
            return jsonify({"error": "Invalid JSON body"}), 400

        url = (data.get("url") or "").strip()
        user_id = data.get("user_id")

        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        # Feature extraction
        features = extract_all_features(url)

        # ML prediction
        result = predict_from_features(features, models, raw_url=url)
        trust_score = float(result.get("trust_score", 0))

        # Save DB history for logged in users
        if user_id:
            try:
                db = get_db()
                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO scan_results (user_id, shopping_url, trust_score, scanned_at)
                    VALUES (%s, %s, %s, NOW())
                """, (user_id, url, trust_score))
                cursor.close()
                db.close()
            except Exception as db_err:
                print("[DB ERROR]", db_err)

        return jsonify({
            "url": url,
            "features": features,
            "result": result
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# /history (same style, improved error handling)
# --------------------------------------------------
@app.route("/history", methods=["GET"])
def history():
    try:
        user_id = request.args.get("user_id")

        if not user_id:
            return jsonify({"error": "Missing user_id"}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, shopping_url, trust_score, scanned_at
            FROM scan_results
            WHERE user_id = %s
            ORDER BY scanned_at DESC
        """, (user_id,))

        rows = cursor.fetchall()

        cursor.close()
        db.close()

        return jsonify({"count": len(rows), "history": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# /scan_results (admin panel)
# --------------------------------------------------
@app.route("/scan_results", methods=["GET"])
def scan_results():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, user_id, shopping_url, trust_score, scanned_at
            FROM scan_results
            ORDER BY scanned_at DESC
            LIMIT 200
        """)

        rows = cursor.fetchall()

        cursor.close()
        db.close()

        return jsonify({"count": len(rows), "results": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# Gunicorn / Local Server Start (same style)
# --------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"🚀 SmellScam API running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
