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

# ------------------------------------------------------------------
# 1) MySQL DB Connection
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
# Load ML models at startup
# ------------------------------------------------------------------
models = load_models()

@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "SmellScam ML API (Flask) is running!"})

# ------------------------------------------------------------------
# 2) PREDICT + optional DB insert
# ------------------------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)

        url = (data.get("url") or "").strip()
        user_id = data.get("user_id")  # sent only when logged in

        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        feats = extract_all_features(url)
        result = predict_from_features(feats, models, raw_url=url)
        trust = result.get("trust_score")

        # ⭐ Insert only for logged-in users
        if user_id:
            try:
                db = get_db()
                cursor = db.cursor()

                cursor.execute("""
                    INSERT INTO scan_results (user_id, shopping_url, trust_score, scanned_at)
                    VALUES (%s, %s, %s, NOW())
                """, (user_id, url, trust))

                cursor.close()
                db.close()
                print("Saved scan result for user:", user_id)

            except Exception as db_err:
                print("DB INSERT ERROR:", db_err)
        else:
            print("Guest user → NOT inserted into database.")

        return jsonify({
            "url": url,
            "features": feats,
            "result": result,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------------------------
# 3) Simple route
# ------------------------------------------------------------------
@app.route("/simple", methods=["POST"])
def simple():
    try:
        url = request.data.decode("utf-8").strip()
        if not url:
            return jsonify({"error": "Missing URL in body"}), 400

        feats = extract_all_features(url)
        result = predict_from_features(feats, models, raw_url=url)

        return jsonify({"url": url, "result": result})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------------------------
# 4) Debug
# ------------------------------------------------------------------
@app.route("/debug", methods=["GET"])
def debug():
    try:
        url = (request.args.get("url") or "").strip()
        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        feats = extract_all_features(url)
        result = predict_from_features(feats, models, raw_url=url)

        return jsonify({
            "url": url,
            "features_extracted": feats,
            "predictor_output": result
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------------------------
# 5) /history
# ------------------------------------------------------------------
@app.route("/history", methods=["GET"])
def history():
    try:
        user_id = request.args.get("user_id")
        db = get_db()
        cursor = db.cursor(dictionary=True)

        if user_id:
            cursor.execute("""
                SELECT id, shopping_url, trust_score, scanned_at
                FROM scan_results
                WHERE user_id = %s
                ORDER BY scanned_at DESC
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT id, shopping_url, trust_score, scanned_at
                FROM scan_results
                ORDER BY scanned_at DESC
            """)

        rows = cursor.fetchall()
        return jsonify({"count": len(rows), "history": rows})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------------------------
# 6) /scan_results (full table)
# ------------------------------------------------------------------
@app.route("/scan_results", methods=["GET"])
def scan_results():
    try:
        user_id = request.args.get("user_id")
        limit  = request.args.get("limit")
        order  = request.args.get("order", "desc").lower()

        if order not in ["asc", "desc"]:
            order = "desc"

        db = get_db()
        cursor = db.cursor(dictionary=True)

        query = "SELECT id, user_id, shopping_url, trust_score, scanned_at FROM scan_results"
        params = []

        if user_id:
            query += " WHERE user_id = %s"
            params.append(user_id)

        query += f" ORDER BY scanned_at {order.upper()}"

        if limit and limit.isdigit():
            query += f" LIMIT {limit}"

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

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
