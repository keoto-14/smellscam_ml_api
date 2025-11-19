# app.py
import os
import traceback
import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# DB CONNECTION
# ---------------------------------------------------------
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        autocommit=True
    )

# Load ML models
models = load_models()


@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "SmellScam API is running"})


# ---------------------------------------------------------
#  PREDICT (Store results correctly)
# ---------------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)

        url = (data.get("url") or "").strip()
        user_id = data.get("user_id")  # null for guests
        user_email = data.get("user_email")  # for logged user
        # user_email comes from PHP session

        if not url:
            return jsonify({"error": "Missing URL"}), 400

        # Extract features + run prediction
        feats = extract_all_features(url)
        result = predict_from_features(feats, models, raw_url=url)
        trust = result.get("trust_score")

        # -------------------------------------------------
        # 1) LOGGED-IN USER → STORE INTO scan_history
        # -------------------------------------------------
        if user_email:
            try:
                db = get_db()
                cursor = db.cursor()

                cursor.execute("""
                    INSERT INTO scan_history (user_email, scan_text, result, date)
                    VALUES (%s, %s, %s, NOW())
                """, (user_email, url, f"{trust}%"))

                cursor.close()
                db.close()

                print("Saved to scan_history:", user_email)

            except Exception as err:
                print("DB ERROR (scan_history):", err)

        # -------------------------------------------------
        # 2) GUEST USER → STORE INTO scan_results
        # -------------------------------------------------
        else:
            try:
                db = get_db()
                cursor = db.cursor()

                cursor.execute("""
                    INSERT INTO scan_results (shopping_url, trust_score, scanned_at)
                    VALUES (%s, %s, NOW())
                """, (url, trust))

                cursor.close()
                db.close()

                print("Saved to scan_results (guest)")

            except Exception as err:
                print("DB ERROR (scan_results):", err)

        # -------------------------------------------------
        # RETURN JSON TO PHP
        # -------------------------------------------------
        return jsonify({
            "url": url,
            "features": feats,
            "result": result,
            "trust_score": trust
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# Run
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
