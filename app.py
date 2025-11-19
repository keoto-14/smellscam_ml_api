import os
import traceback
import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Railway loads environment variables automatically
load_dotenv()

# Force FAST_MODE for Railway to avoid WHOIS/SSL/VT timeouts
os.environ["FAST_MODE"] = "1"

from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ---------------------------------------------
# 1) Safe MySQL connection (with fallback)
# ---------------------------------------------
def get_db():
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS"),
            database=os.getenv("DB_NAME"),
            autocommit=True,
            connection_timeout=5
        )
    except Exception as e:
        print("❌ DB Connection Failed:", str(e))
        return None


# ---------------------------------------------
# 2) Load models (only once)
# ---------------------------------------------
try:
    models = load_models()
    print("✅ ML Models Loaded")
except Exception as e:
    print("❌ MODEL LOAD ERROR:", e)
    models = None


@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "SmellScam ML API is running on Railway!"})


# ---------------------------------------------
# 3) Predict API
# ---------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        url = (data.get("url") or "").strip()
        user_id = data.get("user_id")

        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        # Extract features (FAST_MODE makes this instant)
        features = extract_all_features(url)

        # ML prediction
        result = predict_from_features(features, models, raw_url=url)
        trust_score = result.get("trust_score")

        # Save scan only if user is logged in
        if user_id:
            db = get_db()
            if db:
                try:
                    cursor = db.cursor()
                    cursor.execute("""
                        INSERT INTO scan_results (user_id, shopping_url, trust_score, scanned_at)
                        VALUES (%s, %s, %s, NOW())
                    """, (user_id, url, trust_score))
                    cursor.close()
                    db.close()
                    print(f"💾 Scan saved for user {user_id}")
                except Exception as e:
                    print("❌ DB Insert Error:", e)
            else:
                print("⚠ Skipped DB save (DB offline)")

        return jsonify({
            "url": url,
            "features": features,
            "result": result
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------
# 4) Get user history
# ---------------------------------------------
@app.route("/history", methods=["GET"])
def history():
    try:
        user_id = request.args.get("user_id")
        if not user_id:
            return jsonify({"error": "Missing user_id"}), 400

        db = get_db()
        if not db:
            return jsonify({"error": "Database unavailable"}), 500

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

        return jsonify({
            "count": len(rows),
            "history": rows
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------
# 5) Admin list (latest 200 scans)
# ---------------------------------------------
@app.route("/scan_results", methods=["GET"])
def scan_results():
    try:
        db = get_db()
        if not db:
            return jsonify({"error": "Database unavailable"}), 500

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


# ---------------------------------------------
# Run server
# Railway sets PORT automatically
# ---------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
