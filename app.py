import os
import traceback
import json

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import mysql.connector

# Load .env
load_dotenv()

# ML
from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

# --------------------------------------------------
# Flask App
# --------------------------------------------------
app = Flask(__name__)
CORS(app)

models = load_models()

# --------------------------------------------------
# DB Connection
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
# Root Check
# --------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "running", "service": "SmellScam ML API"})


# --------------------------------------------------
# PREDICT ENDPOINT (Exabytes-safe)
# --------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        # --------------------------------------
        # Exabytes Safe JSON Parsing
        # --------------------------------------
        data = request.get_json(silent=True)

        if not data:
            try:
                raw = request.data.decode("utf-8").strip()
                data = json.loads(raw)
            except:
                return jsonify({"error": "Invalid JSON"}), 400

        # --------------------------------------
        # ONLY ACCEPT "url" (your PHP uses this)
        # --------------------------------------
        url = (data.get("url") or "").strip()
        user_id = data.get("user_id")

        if not url:
            return jsonify({"error": "Missing URL"}), 400

        print("📥 Incoming URL:", url)

        # Extract features
        features = extract_all_features(url)

        # ML Prediction
        result = predict_from_features(features, models, raw_url=url)
        trust_score = result.get("trust_score", 0)

        # --------------------------------------
        # Save to DB (logged in users only)
        # --------------------------------------
        if user_id:
            try:
                db = get_db()
                cur = db.cursor()
                cur.execute(
                    """
                    INSERT INTO scan_results (user_id, shopping_url, trust_score, scanned_at)
                    VALUES (%s, %s, %s, NOW())
                    """,
                    (int(user_id), url, trust_score)
                )
                cur.close()
                db.close()
            except Exception as e:
                print("[DB ERROR]", e)

        # Success Response
        return jsonify({
            "url": url,
            "features": features,
            "result": result
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# USER HISTORY
# --------------------------------------------------
@app.route("/history", methods=["GET"])
def history():
    try:
        user_id = request.args.get("user_id")

        if not user_id:
            return jsonify({"error": "Missing user_id"}), 400

        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, shopping_url, trust_score, scanned_at
            FROM scan_results
            WHERE user_id = %s
            ORDER BY scanned_at DESC
            """,
            (user_id,)
        )
        rows = cur.fetchall()

        cur.close()
        db.close()

        return jsonify({"count": len(rows), "history": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# ADMIN — ALL SCANS
# --------------------------------------------------
@app.route("/scan_results", methods=["GET"])
def scan_results():
    try:
        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, user_id, shopping_url, trust_score, scanned_at FROM scan_results ORDER BY scanned_at DESC LIMIT 200"
        )
        rows = cur.fetchall()

        cur.close()
        db.close()

        return jsonify({"count": len(rows), "results": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# Run Server
# --------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"🚀 SmellScam ML API running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
