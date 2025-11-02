# app.py ✅ FINAL VERSION (for Railway)
import os
import joblib
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from url_feature_extractor import extract_all_features

app = Flask(__name__)
CORS(app)  # allows safe cross-origin requests if needed

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(ROOT_DIR, "models")

def load_any(paths):
    """Tries each path and loads the first existing model file."""
    for p in paths:
        if os.path.exists(p):
            return joblib.load(p)
    raise FileNotFoundError(f"Model not found. Tried: {paths}")

# ---- Load models ----
rf_model = load_any([os.path.join(MODEL_DIR, "rf_model.pkl"), "rf_model.pkl"])
nb_model = load_any([os.path.join(MODEL_DIR, "nb_model.pkl"), "nb_model.pkl"])

try:
    xgb_model = load_any([os.path.join(MODEL_DIR, "xgb_model.pkl"), "xgb_model.pkl"])
except:
    xgb_model = None

features_list = load_any([
    os.path.join(MODEL_DIR, "feature_list.pkl"),
    os.path.join(MODEL_DIR, "feature_columns.pkl"),
    "feature_list.pkl",
    "feature_columns.pkl"
])

try:
    imputer = load_any([os.path.join(MODEL_DIR, "imputer.pkl"), "imputer.pkl"])
except:
    imputer = None

print("✅ Models Loaded")
print("Features:", len(features_list))

# ------------------------------------
def prepare_input_df(features_dict):
    row = {f: features_dict.get(f, 0) for f in features_list}
    df = pd.DataFrame([row])
    df = df.replace([np.inf, -np.inf], np.nan)

    if imputer:
        arr = imputer.transform(df)
        df = pd.DataFrame(arr, columns=features_list)
    else:
        df = df.fillna(0)

    return df

@app.route("/healthz")
def health():
    return "OK", 200

@app.route("/")
def index():
    return render_template("index.html")

def extract_url_from_request():
    url = ""
    if request.form.get("url"):
        url = request.form.get("url").strip()
    elif request.is_json:
        try:
            data = request.get_json(force=True)
            url = data.get("url", "").strip()
        except:
            pass
    else:
        try:
            raw = request.data.decode("utf-8")
            if raw.startswith("url="):
                url = raw.replace("url=", "").strip()
        except:
            pass
    return url

@app.route("/api/predict", methods=["POST"])
def api_predict():
    url = extract_url_from_request()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return run_prediction(url, html_output=False)

@app.route("/predict", methods=["POST"])
def web_predict():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template("result.html", url=url, prediction="Invalid URL", trust_score=0, details={})
    return run_prediction(url, html_output=True)

def run_prediction(url, html_output):
    try:
        feats = extract_all_features(url)
    except Exception as e:
        if html_output:
            return render_template("result.html", url=url, prediction="Error Extracting Features", trust_score=0, details={"error": str(e)})
        return jsonify({"error": f"Feature extraction failed: {str(e)}"}), 500

    df = prepare_input_df(feats)

    # Model probabilities
    rf = float(rf_model.predict_proba(df)[:, 1][0])
    nb = float(nb_model.predict_proba(df)[:, 1][0])
    xgb = None
    if xgb_model:
        try:
            xgb = float(xgb_model.predict_proba(df)[:, 1][0])
        except:
            pass

    model_score = (0.6 * rf + 0.4 * nb) if xgb is None else (0.5 * rf + 0.3 * nb + 0.2 * xgb)

    # Live signals
    vt = float(feats.get("VT_Detection_Ratio", 0))
    quad9 = int(feats.get("Quad9_Blocked", 0))
    ssl = int(feats.get("SSL_Valid", 0))
    age = int(feats.get("Domain_Age_Days", 0) or 0)

    live_mult = 1.0
    live_mult *= 1.2 if vt == 0 else 0.9 if vt < 0.02 else 0.6 if vt < 0.1 else 0.3
    live_mult *= 0.25 if quad9 else 1.05
    live_mult *= 1.02 if ssl else 0.85
    if age < 30:
        live_mult *= 0.6
    elif age < 180:
        live_mult *= 0.85
    elif age < 1000:
        live_mult *= 1.05
    else:
        live_mult *= 1.15

    ML_WEIGHT = float(os.getenv("ML_WEIGHT", 0.7))
    live_mult = max(0.05, min(live_mult, 2.5))
    final = ML_WEIGHT * (1 - model_score) + (1 - ML_WEIGHT) * (live_mult * 0.9)
    trust = round(max(0, min(final, 1)) * 100, 2)

    label = "PHISHING" if trust < 50 else "SUSPICIOUS" if trust < 75 else "LEGITIMATE"

    details = {
        "rf_prob": rf, "nb_prob": nb, "xgb_prob": xgb,
        "vt_malicious": vt, "quad9_blocked": quad9, "ssl_valid": ssl, "domain_age_days": age
    }

    if html_output:
        return render_template("result.html", url=url, prediction=label, trust_score=trust, details=details)
    return jsonify({"url": url, "prediction": label, "trust_score": trust, "details": details})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
