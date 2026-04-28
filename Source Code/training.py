"""
training.py  —  Train Random Forest model for IDPS
Run: python training.py
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
import joblib
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("  IDPS MODEL TRAINING")
print("=" * 60)

file_path = "data/KDDCup99.csv"

columns = [
    "id", "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "lnum_compromised", "lroot_shell", "lsu_attempted", "lnum_root",
    "lnum_file_creations", "lnum_shells", "lnum_access_files", "lnum_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
]

print("\n[1] Loading dataset...")
data = pd.read_csv(file_path, header=None, names=columns, low_memory=False)
print(f"    Total rows: {len(data):,}")

def map_attack_category(label):
    if label == "normal":
        return "normal"
    elif label in ["neptune", "smurf", "pod", "teardrop", "back", "land", "apache2", "udpstorm"]:
        return "DoS"
    elif label in ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"]:
        return "Probe"
    elif label in ["buffer_overflow", "loadmodule", "rootkit", "perl", "httptunnel", "ps", "sqlattack", "xterm"]:
        return "U2R"
    elif label in ["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
                   "warezclient", "spy", "snmpguess", "snmpgetattack", "sendmail", "named",
                   "xlock", "xsnoop", "worm"]:
        return "R2L"
    else:
        return None

print("\n[2] Mapping attack labels...")
data['label'] = data['label'].astype(str).apply(map_attack_category)
data = data[data['label'].notna()]
print(f"    Rows after filtering: {len(data):,}")

if len(data) > 100000:
    print("\n    Sampling 100,000 rows for faster training...")
    data = data.sample(n=100000, random_state=42, replace=False)
    print(f"    Sampled rows: {len(data):,}")

label_counts = data['label'].value_counts()
print("\n    Class distribution:")
for lbl, cnt in label_counts.items():
    print(f"      {lbl}: {cnt:,}")

print("\n[3] Encoding categorical variables...")
cat_cols = ["protocol_type", "service", "flag"]
data = pd.get_dummies(data, columns=cat_cols, drop_first=False)

print("\n[4] Encoding target labels...")
label_encoder = LabelEncoder()
data['label'] = label_encoder.fit_transform(data['label'])
print(f"    Classes: {list(label_encoder.classes_)}")

print("\n[5] Preparing features and target...")
X = data.drop(["id", "label"], axis=1)
y = data["label"]
print(f"    Features: {X.shape[1]}")
print(f"    Target classes: {len(label_encoder.classes_)}")

print("\n[6] Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
print(f"    Training: {len(X_train):,}, Testing: {len(X_test):,}")

print("\n[7] Balancing classes with SMOTE...")
smote = SMOTE(random_state=42, n_jobs=-1)
X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
print(f"    After SMOTE: {len(X_train_balanced):,}")

unique, counts = np.unique(y_train_balanced, return_counts=True)
print("    Balanced distribution:")
for idx, cnt in zip(unique, counts):
    class_name = label_encoder.inverse_transform([idx])[0]
    print(f"      {class_name}: {cnt:,}")

print("\n[8] Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=5,
    class_weight="balanced",
    max_features="sqrt",
    n_jobs=4,
    random_state=42,
    verbose=0
)

model.fit(X_train_balanced, y_train_balanced)

print("\n[9] Evaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n    Accuracy: {accuracy:.4f}")

print("\n    Classification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

print("\n    Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"    {label_encoder.classes_}")
print(cm)

print("\n[10] Saving model and artifacts...")
joblib.dump(model, "models/rf_model_resampled.pkl")
joblib.dump(label_encoder, "models/label_encoder_resampled.pkl")
joblib.dump(list(X.columns), "models/encoded_columns_resampled.pkl")
print("    Saved: models/rf_model_resampled.pkl")
print("    Saved: models/label_encoder_resampled.pkl")
print("    Saved: models/encoded_columns_resampled.pkl")

print("\n    Feature Importances (Top 10):")
importances = model.feature_importances_
indices = np.argsort(importances)[::-1][:10]
for i, idx in enumerate(indices):
    print(f"      {i+1}. {X.columns[idx]}: {importances[idx]:.4f}")

print("\n" + "=" * 60)
print("  TRAINING COMPLETE")
print("=" * 60)