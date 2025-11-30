import os
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import mysql.connector

# Load environment variables
load_dotenv()

# ML imports
from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

# --------------------------------------------------
# Flask Init
# --------------------------------------------------
app = Flask(__name__)
CORS(app)

# Load ML models once (fast)
models = load_models()


# --------------------------------------------------
# DB Helper
# --------------------------------------------------
def get_db():
    """Return MySQL connection."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        autocommit=True
    )


@app.route("/db_test")
def db_test():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_results;")
        rows = cursor.fetchone()[0]
        cursor.close()
        db.close()
        return {"db": "connected", "rows": rows}
    except Exception as e:
        return {"db": "error", "error": str(e)}


# --------------------------------------------------
# Root
# --------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "running",
        "service": "SmellScam ML API",
        "fast_mode": os.getenv("FAST_MODE", "0")
    })


# --------------------------------------------------
# /predict  — MAIN ENDPOINT
# --------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Parse JSON body
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Invalid JSON body"}), 400

        # Accept either "url" (your backend) or "target" (your PHP form)
        url = (data.get("url") or data.get("target") or "").strip()
        user_id = data.get("user_id")

        if not url:
            return jsonify({"error": "Missing URL"}), 400

        print("📥 Incoming URL:", url)

        # Extract all ML + live features
        features = extract_all_features(url)

        # Perform ML prediction
        result = predict_from_features(features, models, raw_url=url)
        trust_score = result.get("trust_score", 0)

        # ------------------------------------------------------
        # SAVE SCAN ONLY IF USER LOGGED IN
        # ------------------------------------------------------
        if user_id:
            try:
                db = get_db()
                cursor = db.cursor()

                cursor.execute(
                    """
                    INSERT INTO scan_results (user_id, shopping_url, trust_score, scanned_at)
                    VALUES (%s, %s, %s, NOW())
                    """,
                    (int(user_id), url, trust_score)
                )

                cursor.close()
                db.close()
            except Exception as db_err:
                print("[DB ERROR]", db_err)

        # Return backend response
        return jsonify({
            "target": url,
            "features": features,
            "result": result
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# /history
# --------------------------------------------------
@app.route("/history", methods=["GET"])
def history():
    try:
        user_id = request.args.get("user_id")
        if not user_id:
            return jsonify({"error": "Missing user_id"}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, shopping_url, trust_score, scanned_at
            FROM scan_results
            WHERE user_id = %s
            ORDER BY scanned_at DESC
            """,
            (user_id,)
        )

        rows = cursor.fetchall()
        cursor.close()
        db.close()

        return jsonify({"count": len(rows), "history": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# Admin: All Scan Results
# --------------------------------------------------
@app.route("/scan_results", methods=["GET"])
def scan_results():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, user_id, shopping_url, trust_score, scanned_at
            FROM scan_results
            ORDER BY scanned_at DESC
            LIMIT 200
            """
        )

        rows = cursor.fetchall()

        cursor.close()
        db.close()

        return jsonify({"count": len(rows), "results": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# Server Start
# --------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"🚀 SmellScam API running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
