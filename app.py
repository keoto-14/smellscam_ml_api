import os
import traceback
import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load env var (Railway UI sets them, no .env needed)
load_dotenv()

from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------------
# 1) MySQL DB Connection (Railway MySQL)
# ------------------------------------------------------------------
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        autocommit=True
    )


# ------------------------------------------------------------------
# Load ML models once (fast!)
# ------------------------------------------------------------------
models = load_models()


@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "SmellScam ML API is running!"})


# ------------------------------------------------------------------
# 2) Predict API (Main endpoint)
# ------------------------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)

        url = (data.get("url") or "").strip()
        user_id = data.get("user_id")  # only sent if logged in

        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        # Extract features + model prediction
        features = extract_all_features(url)
        result = predict_from_features(features, models, raw_url=url)
        trust_score = result.get("trust_score")

        # Save ONLY if logged in
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

                print(f"[DB] Saved scan for user_id={user_id}")
            except Exception as e:
                print("DB ERROR:", e)

        else:
            print("Guest user → Result NOT saved in database.")

        return jsonify({
            "url": url,
            "features": features,
            "result": result,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ------------------------------------------------------------------
# 3) History for user
# ------------------------------------------------------------------
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


# ------------------------------------------------------------------
# 4) Optional: fetch all results (admin/debug)
# ------------------------------------------------------------------
@app.route("/scan_results", methods=["GET"])
def scan_results():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
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


# ------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
