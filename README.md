# AI-Based Personal Cybersecurity Assistant

An intelligent, real-time URL threat detector that utilizes a Random Forest classifier paired with rule-based heuristics to identify phishing websites. The application is powered by **Explainable AI (XAI)** principles, providing user-facing explanations detailing why a website was flagged.

---

## 🚀 Key Features

- **Machine Learning Engine**: Trained on the extensive **PhiUSIIL Phishing URL Dataset** using a Random Forest Classifier.
- **Rule-Based Heuristics**: Custom threat-scoring heuristics (checking keywords, hyphens, protocol type, length, digit density) layer on top of ML predictions.
- **Explainable AI (XAI)**: Generates human-readable explanations of detected risk indicators for transparency.
- **Premium Glassmorphic UI**: Sleek, fully responsive modern interface designed with dark theme styles and responsive elements.
- **Normalized URL Logic**: Intelligent preprocessing that resolves standard dataset biases (e.g. overfitting on the presence of `www.`).

---

## 🛠️ Installation & Setup

Ensure you have **Python 3.10+** installed.

1. **Activate the Virtual Environment**:
   - **Windows (PowerShell)**:
     ```powershell
     .\venv\Scripts\Activate.ps1
     ```
   - **Windows (CMD)**:
     ```cmd
     .\venv\Scripts\activate.bat
     ```
   - **Linux / macOS**:
     ```bash
     source venv/bin/activate
     ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🏃 Running the Application

### Option A: One-Click Run (Windows)
Double-click the **`run_app.bat`** file in the project folder to automatically activate the environment and launch the server.

### Option B: Terminal Command
With the virtual environment activated, run:
```bash
python app.py
```
The Flask development server will start at `http://127.0.0.1:5000/`. Open this address in your web browser to access the assistant.

---

## 🧠 Retraining the Model

If you want to train the model from scratch on the dataset:
```bash
python train_model.py
```
This loads `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`, extracts normalized syntactic features, trains a Random Forest model, prints accuracy statistics, and saves the new model to `phishing_model.pkl`.

---

## 🔍 Bug Fixes & Improvements

1. **Bare Domain Dataset Bias Resolved**: 
   Legitimate URLs in the training dataset almost exclusively used `www.legitdomain.com` (having $\ge 1$ subdomains and $\ge 2$ dots), while phishing URLs often didn't. This caused the model to overfit and classify safe bare domains (like `google.com` or `github.com`) as 100% Phishing. We added an automatic **URL Normalization Step** in `feature_extraction.py` that prepends `www.` to bare domains during training and inference, fixing this bug without decreasing ML test set accuracy.
2. **Robust Relative Path Resolution**:
   Fixed potential `FileNotFoundError` exceptions by resolving the file locations of `phishing_model.pkl` and `dataset/` relative to the running script's directory.
3. **Double Backslash Formatting Error**:
   Replaced literal `\\n` outputs in `train_model.py` print statements with standard newline characters `\n` for cleaner console readability.
4. **UI Styling Overhaul**:
   Transformed a basic plain HTML frontend into a high-fidelity glassmorphism interface featuring custom Google Fonts (Outfit & Inter), beautiful threat-colored explanation cards, and an interactive risk indicator.
