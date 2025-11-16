# SmellScam ML API (FastAPI - Hybrid ML+VT+GSB)

## Overview
FastAPI backend that returns phishing predictions using a hybrid of:
- ML (XGBoost + RandomForest + Stacker)
- VirusTotal domain report
- Google Safe Browsing

Weights: **ML 50% | VT 30% | GSB 20%**

Frontend (PHP) remains unchanged; it calls `/predict`.

## Files
- `app.py` - FastAPI app with `/predict`, `/simple`, `/debug`
- `predictor.py` - hybrid scoring logic
- `url_feature_extractor.py` - deterministic lexical features
- `simple_cache.py` - TTL cache for VT/GSB
- `models/` - put your model files here (`xgb.json`, `rf.pkl`, `stacker.pkl`, `features.pkl`)
- `requirements.txt`, `Procfile`

## Local setup
1. Create venv:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
