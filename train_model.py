import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

from feature_extraction import extract_features


# Get script's absolute directory path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =========================
# LOAD DATASET
# =========================

dataset_path = os.path.join(BASE_DIR, 'dataset', 'PhiUSIIL_Phishing_URL_Dataset.csv')
data = pd.read_csv(dataset_path)

print("Dataset Loaded Successfully")


# =========================
# EXTRACT URLS & LABELS
# =========================

urls = data['URL']
labels = data['label']
print(labels.value_counts())


# =========================
# GENERATE FEATURES
# =========================

feature_list = []

for url in urls:

    extracted = extract_features(str(url))

    feature_list.append(extracted)


# Convert to dataframe
X = pd.DataFrame(feature_list)

# Labels
y = labels


# =========================
# VERIFY FEATURE COUNT
# =========================

print("Feature Count:", len(X.columns))


# =========================
# TRAIN TEST SPLIT
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)


# =========================
# MODEL TRAINING
# =========================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)


# =========================
# PREDICTIONS
# =========================

y_pred = model.predict(X_test)


# =========================
# EVALUATION
# =========================

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

print("\nClassification Report:\n")

print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:\n")

print(confusion_matrix(y_test, y_pred))


# =========================
# SAVE MODEL
# =========================

model_path = os.path.join(BASE_DIR, 'phishing_model.pkl')
joblib.dump(model, model_path)

print("\nModel saved successfully!")