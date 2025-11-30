import os
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import mysql.connector

# ML imports
from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

# Load local env (Railway auto loads)
load_dotenv()

# Flask initialize
app = Flask(__name__)
CORS(app)

# Load ML models once at startup
models = load_models()


# ------------------------------------------------------
# DB CONNECTION
# ------------------------------------------------------
def get_db():
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
        cur = db.cursor()
        cur.execute("SELECT COUNT(*) FROM scan_results")
        count = cur.fetchone()[0]
        return {"db": "connected", "rows": count}
    except Exception as e:
        return {"db": "failed", "error": str(e)}


# ------------------------------------------------------
# Root endpoint
# ------------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "running",
        "service": "SmellScam ML API",
        "fast_mode": os.getenv("FAST_MODE", "0")
    })


# ------------------------------------------------------
#  FIXED /predict endpoint (NO MORE 400)
# ------------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Accept JSON (if PHP sends it)
        data = request.get_json(silent=True)

        # Accept form POST (cPanel/php-fpm fallback)
        if not data:
            data = {
                "url": request.form.get("shopping_url") or request.form.get("url"),
                "user_id": request.form.get("user_id")
            }

        if not data or not data.get("url"):
            return jsonify({"error": "Missing 'url'"}), 400

        url = data["url"].strip()
        user_id = data.get("user_id")

        # Extract features
        features = extract_all_features(url)

        # ML prediction
        result = predict_from_features(features, models, raw_url=url)
        trust_score = float(result.get("trust_score", 0))

        # Save DB only if logged in
        if user_id:
            try:
                db = get_db()
                cur = db.cursor()
                cur.execute(
                    """
                    INSERT INTO scan_results (user_id, shopping_url, trust_score, scanned_at)
                    VALUES (%s, %s, %s, NOW())
                    """,
                    (user_id, url, trust_score)
                )
                cur.close()
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


# ------------------------------------------------------
# USER HISTORY
# ------------------------------------------------------
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


# ------------------------------------------------------
# ADMIN — Last 200 scans
# ------------------------------------------------------
@app.route("/scan_results", methods=["GET"])
def scan_results():
    try:
        db = get_db()
        cur = db.cursor(dictionary=True)

        cur.execute(
            """
            SELECT id, user_id, shopping_url, trust_score, scanned_at
            FROM scan_results
            ORDER BY scanned_at DESC
            LIMIT 200
            """
        )

        rows = cur.fetchall()

        cur.close()
        db.close()

        return jsonify({"count": len(rows), "results": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ------------------------------------------------------
# RUN (LOCAL ONLY)
# ------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"🚀 SmellScam API running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
