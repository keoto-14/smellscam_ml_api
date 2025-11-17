import os
return False




# VirusTotal domain report
VT_API_KEY = os.environ.get("VT_API_KEY")


def vt_domain_report(domain):
if not VT_API_KEY:
return 0, 0, 0.0
cache_key = f"vt::{domain}"
cached = cache_get(cache_key)
if cached:
return cached.get("total",0), cached.get("mal",0), cached.get("ratio",0.0)
try:
headers = {"x-apikey": VT_API_KEY}
url = f"https://www.virustotal.com/api/v3/domains/{domain}"
r = requests.get(url, headers=headers, timeout=6)
if r.status_code == 200:
stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
total = sum(stats.values()) if isinstance(stats, dict) else 0
mal = stats.get("malicious", 0) if isinstance(stats, dict) else 0
ratio = mal / total if total > 0 else 0.0
cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
return total, mal, ratio
except Exception:
traceback.print_exc()
cache_set(cache_key, {"total": 0, "mal": 0, "ratio": 0.0})
return 0, 0, 0.0




# Main predictor
def predict_from_features(features, models, raw_url=None):
feature_names = models["features"]
X = np.array([[features.get(f, 0) for f in feature_names]], dtype=float)
try:
p_xgb = float(models["xgb"].predict_proba(X)[0][1])
except Exception:
traceback.print_exc(); p_xgb = 0.5
try:
p_rf = float(models["rf"].predict_proba(X)[0][1])
except Exception:
traceback.print_exc(); p_rf = 0.5
stack_input = np.array([[p_xgb, p_rf]])
try:
final_ml = float(models["stacker"].predict_proba(stack_input)[0][1])
except Exception:
final_ml = (p_xgb + p_rf) / 2
ml_risk = final_ml * 100


# vt
domain = ""
try:
domain = urllib.parse.urlparse(raw_url or features.get("url", "")).netloc.split(":")[0].lower()
except Exception:
domain = ""
vt_total, vt_mal, vt_ratio = vt_domain_report(domain)
vt_risk = (vt_ratio * 100)


# gsb
gsb_match = check_gsb(raw_url)
gsb_risk = 100.0 if gsb_match else 0.0


# weights
final_risk = (0.20 * gsb_risk) + (0.30 * vt_risk) + (0.50 * ml_risk)
final_risk = max(0.0, min(100.0, final_risk))
trust_score = 100.0 - final_risk


if gsb_match:
prediction = "phishing"
else:
prediction = "phishing" if final_risk >= 50.0 else "safe"


return {
"prediction": prediction,
"trust_score": round(trust_score, 6),
"risk_score": round(final_risk, 6),
"gsb_match": bool(gsb_match),
"vt": {"total_vendors": int(vt_total), "malicious": int(vt_mal), "ratio": float(vt_ratio)},
"model_probs": {"xgb": float(p_xgb), "rf": float(p_rf), "ml_final_prob": float(final_ml)}
}
