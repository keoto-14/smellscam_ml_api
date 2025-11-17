# SmellScam ML API (Hybrid: ML+VT+Rules)

## Quick start (local)
1. Create venv:
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
2. Install:
   pip install -r requirements.txt
3. Place trained models in `models/`:
   - models/xgb.json
   - models/rf.pkl
   - models/stacker.pkl
   - models/features.pkl
4. Set environment variables:
   - VT_API_KEY (optional but recommended)
   - GSB_API_KEY (optional)
   - ML_WEIGHT, VT_WEIGHT, RULE_WEIGHT (optional, floats)
5. Run:
   uvicorn app:app --reload
6. Test:
   POST /predict JSON { "url": "https://example.com" }

## Notes
- Train locally using train_pipeline_40.py
- XGBoost saved as JSON to avoid version/pickle mismatch
