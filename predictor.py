import pickle
import numpy as np
from url_feature_extractor import extract_all_features

ML_WEIGHT = 0.50
VT_WEIGHT = 0.45
GSB_WEIGHT = 0.05

class Predictor:
    def __init__(self, rf_path="models/rf.pkl", xgb_path="models/xgb.json",
                 stacker_path="models/stacker.pkl", features_path="models/features.pkl"):

        # Load models
        self.rf = pickle.load(open(rf_path, "rb"))

        # Load XGBoost
        from xgboost import XGBClassifier
        self.xgb = XGBClassifier()
        self.xgb.load_model(xgb_path)

        # Stacker (logistic regression)
        self.stacker = pickle.load(open(stacker_path, "rb"))

        # feature ordering
        self.feature_names = pickle.load(open(features_path, "rb"))

        self._loaded = True

    def to_vector(self, f: dict):
        return np.array([f[k] for k in self.feature_names]).reshape(1, -1)

    async def predict_url(self, url: str):
        f = extract_all_features(url)

        # Strict shopping-only mode
        if f.get("is_shopping", 1) == 0:
            return {
                "is_shopping": False,
                "trust_score": None,
                "classification": "non-shopping",
                "model_probs": {}
            }

        X = self.to_vector(f)

        # -----------------------------------------
        # 1) ML model predictions
        # -----------------------------------------

        # RF
        try:
            rf_prob = float(self.rf.predict_proba(X)[0][1])
        except:
            rf_prob = float(self.rf.predict(X)[0])

        # XGB
        try:
            xgb_prob = float(self.xgb.predict_proba(X)[0][1])
        except:
            xgb_prob = float(self.xgb.predict(X)[0])

        # Final ML combiner
        stack_input = np.array([[xgb_prob, rf_prob]])
        try:
            ml_final = float(self.stacker.predict_proba(stack_input)[0][1])
        except:
            ml_final = (xgb_prob + rf_prob) / 2

        # ML trust = prediction of "safe"
        ml_trust = (1 - ml_final) * 100

        # -----------------------------------------
        # 2) VirusTotal trust
        # -----------------------------------------
        vt_total = f.get("vt_total_vendors", 0)
        vt_mal = f.get("vt_malicious_count", 0)

        if vt_total > 0:
            vt_ratio = vt_mal / vt_total
            vt_trust = (1 - vt_ratio) * 100
        else:
            vt_trust = 100

        # -----------------------------------------
        # 3) Google Safe Browsing trust
        # -----------------------------------------
        gsb_safe = not f.get("gsb_match", False)
        gsb_trust = 100 if gsb_safe else 0

        # -----------------------------------------
        # 4) Weighted final score
        # -----------------------------------------
        final_trust = (
            ml_trust * ML_WEIGHT +
            vt_trust * VT_WEIGHT +
            gsb_trust * GSB_WEIGHT
        )

        final_trust = round(final_trust, 3)

        # -----------------------------------------
        # 5) Classification
        # -----------------------------------------
        if final_trust >= 70:
            cls = "legit"
        elif final_trust >= 40:
            cls = "suspicious"
        else:
            cls = "phishing"

        # -----------------------------------------
        # 6) Return structure
        # -----------------------------------------
        return {
            "is_shopping": True,
            "trust_score": final_trust,
            "classification": cls,
            "model_probs": {
                "xgb": xgb_prob,
                "rf": rf_prob,
                "ml_final": ml_final
            }
        }
