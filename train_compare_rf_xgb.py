# train_compare_rf_xgb.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier
import joblib
import os

# ======== CONFIG ========
# Change this to your dataset path
CSV_PATH = "Phishing_Legitimate_full.csv"   # <-- edit if your file has another name

# ========================

print(f"Loading dataset: {CSV_PATH}")
if not os.path.exists(CSV_PATH):
    raise FileNotFoundError(f"Dataset not found: {CSV_PATH}")

df = pd.read_csv(CSV_PATH)
print("✅ Loaded dataset with shape:", df.shape)

# Detect label column automatically
label_col = None
for col in ["status", "label", "CLASS_LABEL", "Result"]:
    if col in df.columns:
        label_col = col
        break

if label_col is None:
    raise ValueError("❌ Could not find label column (expected one of: status, label, CLASS_LABEL, Result)")

print(f"Detected label column: {label_col}")

# Drop non-feature columns
X = df.drop(columns=[label_col, "url"], errors="ignore")
y = df[label_col]

# Normalize label values
y = y.replace({
    "legitimate": 0, "benign": 0, "good": 0,
    "phishing": 1, "malicious": 1, "bad": 1,
    2: 0, 1: 1
}).astype(int)

# Handle missing values
imputer = SimpleImputer(strategy="median")
X_imputed = pd.DataFrame(imputer.fit_transform(X), columns=X.columns)

# Save imputer and feature names
joblib.dump(imputer, "imputer.pkl")
joblib.dump(list(X.columns), "models/feature_columns.pkl")
print("💾 Saved imputer.pkl and feature_columns.pkl")

# Encode labels
le = LabelEncoder()
y_encoded = le.fit_transform(y)
joblib.dump(le, "label_encoder.pkl")

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X_imputed, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# ===== Random Forest =====
print("\n🌲 Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=300,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)
rf_acc = accuracy_score(y_test, rf_pred)
print(f"✅ Random Forest accuracy: {rf_acc:.4f}")
print(classification_report(y_test, rf_pred, target_names=["legitimate", "phishing"]))
joblib.dump(rf, "rf_model.pkl")
print("💾 Saved rf_model.pkl")

# ===== XGBoost =====
print("\n⚡ Training XGBoost...")
xgb = XGBClassifier(
    n_estimators=300,
    learning_rate=0.05,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss"
)
xgb.fit(X_train, y_train)
xgb_pred = xgb.predict(X_test)
xgb_acc = accuracy_score(y_test, xgb_pred)
print(f"✅ XGBoost accuracy: {xgb_acc:.4f}")
print(classification_report(y_test, xgb_pred, target_names=["legitimate", "phishing"]))
joblib.dump(xgb, "xgb_model.pkl")
print("💾 Saved xgb_model.pkl")

# ===== Summary =====
print("\n================= RESULTS =================")
print(f"Random Forest accuracy: {rf_acc:.4f}")
print(f"XGBoost accuracy:       {xgb_acc:.4f}")
print("===========================================")
print("✅ Training complete! You can now run your Flask app.")
