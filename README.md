# Optimized Universal Analyzer

A **fast, futuristic** web-based APK & EXE privacy/risk analyzer built with **Flask** and **Androguard**, featuring:

- **APK Scan** (Fast & Deep modes)
- **EXE Scan** (static imports & string analysis)
- **Real-time progress bar** during scan
- **Risk scoring** with a circular gauge chart
- **Advanced futuristic report UI**
- **Downloadable HTML report**

---

## 📂 Project Structure

optimized_universal_analyzer/
├── app.py # Main Flask application
├── static/ # CSS, JS, and frontend assets
│ ├── style.css
│ ├── script.js
│ └── chart.min.js
├── templates/ # HTML templates
│ ├── index.html # Home page / scan upload
│ └── report.html # Scan result report
├── uploads/ # Temporary file uploads
├── reports/ # Saved HTML reports
├── requirements.txt # Python dependencies
└── README.md # Project documentation

yaml
Copy
Edit

---

## 🚀 Features

### 🔹 APK Scanning
- **Fast Mode:** Parses APK manifest & permissions only → **2-3× faster**.
- **Deep Mode:** Parses APK + DEX for risky APIs.

### 🔹 EXE Scanning
- Extracts imports & suspicious strings for potential malware/ransomware hints.

### 🔹 UI Enhancements
- Real-time AJAX **progress bar** tied to scan steps.
- Futuristic **risk gauge** with Chart.js.
- Collapsible details for findings.
- Downloadable HTML report.

---

## 🛠️ Installation & Usage

### 1️⃣ Clone or Download the Project
```bash
unzip optimized_universal_analyzer.zip
cd optimized_universal_analyzer
2️⃣ Create Virtual Environment & Install Dependencies
bash
Copy
Edit
python -m venv .venv
# Activate venv
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate

pip install -r requirements.txt
3️⃣ Run the Application
bash
Copy
Edit
python app.py
4️⃣ Access in Browser
Open:

cpp
Copy
Edit
http://127.0.0.1:5000
📊 Scan Modes
Mode	Speed	Features
Fast	⚡ Fastest	Manifest, Permissions
Deep	🕵️ Slower	Manifest, Permissions, Risky APIs (DEX)

📦 Dependencies
Flask

Androguard

pefile (for EXE analysis)

Chart.js (frontend)

jQuery (frontend)

Install via:

bash
Copy
Edit
pip install -r requirements.txt
📌 Notes
APK scanning requires Androguard (Python-based APK/Dex parser).

EXE scanning is static only (no sandbox execution).

Upload limits are set to 50MB by default (configurable in app.py).

🛡 Disclaimer
This tool is for educational and security research purposes only.
Do not use it on files you do not own or have permission to analyze.
