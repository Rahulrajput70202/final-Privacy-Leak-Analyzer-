#!/usr/bin/env python3
import os
import json
import time
import uuid
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, render_template, abort, jsonify
from werkzeug.utils import secure_filename

# Lazy imports are used inside analysis functions to speed app startup
# APK deep analysis uses Androguard; EXE uses pefile

app = Flask(__name__, static_folder="static", template_folder="templates")

# --- Configuration ---
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# --- Shared task state (in-memory) ---
TASKS = {}  # task_id -> dict
TASKS_LOCK = threading.Lock()

# --- APK Analysis Configuration ---
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.READ_CONTACTS',
    'android.permission.SEND_SMS',
    'android.permission.INSTALL_PACKAGES'
}

# --- EXE Analysis Configuration ---
SUSPICIOUS_IMPORTS = {
    'socket','send','recv','connect','inet_addr','gethostbyname',
    'CreateRemoteThread','WriteProcessMemory','OpenProcess','VirtualAllocEx',
    'SetWindowsHookExA','GetAsyncKeyState','GetKeyState',
    'CreateFileA','WriteFile','ReadFile','RegCreateKeyExA','RegSetValueExA'
}
SUSPICIOUS_STRINGS = [b'http://', b'https://', b'keylog', b'stealer', b'exploit']

# --- Utility ---
def init_task(mode="fast"):
    task_id = uuid.uuid4().hex
    with TASKS_LOCK:
        TASKS[task_id] = {
            "progress": 0,
            "status": "Queued…",
            "done": False,
            "result": None,
            "error": None,
            "report_path": None,
            "mode": mode
        }
    return task_id

def set_progress(task_id, progress=None, status=None, **kw):
    with TASKS_LOCK:
        task = TASKS.get(task_id)
        if not task:
            return
        if progress is not None:
            task["progress"] = max(task["progress"], int(progress))
        if status is not None:
            task["status"] = status
        for k,v in kw.items():
            task[k] = v

# --- APK Analysis (Fast & Deep) ---
def analyze_apk_fast(apk_path, task_id):
    """Fast mode: manifest/permissions only (no DEX). Very quick."""
    set_progress(task_id, 12, "Parsing APK (fast)…")
    from androguard.core.bytecodes.apk import APK  # lazy import
    apk = APK(apk_path, raw=True)
    set_progress(task_id, 28, "Extracting permissions…")
    used_permissions = set(apk.get_permissions())
    risky_permissions = used_permissions.intersection(DANGEROUS_PERMISSIONS)

    # Optional: simple cleartext traffic hint from manifest (best-effort)
    insecure_apis = []
    try:
        axml = apk.get_android_manifest_xml()
        # look for usesCleartextTraffic="true"
        if axml and b'usesCleartextTraffic="true"' in apk.get_android_manifest_axml().get_buff():
            insecure_apis.append("Manifest allows cleartext traffic")
    except Exception:
        pass

    set_progress(task_id, 70, "Scoring…")
    score = len(risky_permissions)*2 + len(insecure_apis)*2
    max_score = 12*2 + 5*2  # heuristic

    result = {
        "file_type": "Android APK",
        "app_name": apk.get_app_name(),
        "package": apk.get_package(),
        "details_list": sorted(used_permissions),
        "risky_list": sorted(risky_permissions),
        "insecure_list": insecure_apis,
        "risk_score": int(score),
        "max_score": int(max_score),
        "risk_level": "High" if score > 10 else "Medium" if score > 5 else "Low",
        "headings": {
            "details": "🔐 Used Permissions",
            "risky": "🚨 Risky Permissions",
            "insecure": "🛡️ Insecure Config / APIs"
        }
    }
    set_progress(task_id, 88, "Finalizing…")
    return result

def analyze_apk_deep(apk_path, task_id):
    """Deep mode: includes selective DEX analysis for risky APIs."""
    set_progress(task_id, 10, "Parsing APK (deep)…")
    from androguard.misc import AnalyzeAPK  # lazy import
    a, _, dx = AnalyzeAPK(apk_path)

    set_progress(task_id, 30, "Extracting permissions…")
    used_permissions = set(a.get_permissions())
    risky_permissions = used_permissions.intersection(DANGEROUS_PERMISSIONS)

    insecure_apis = []
    # selective method scans (keep minimal for speed)
    set_progress(task_id, 52, "Scanning WebView bridges…")
    if list(dx.find_methods(classname="Landroid/webkit/WebView;", methodname="addJavascriptInterface")):
        insecure_apis.append("WebView -> addJavascriptInterface (Potential RCE)")

    set_progress(task_id, 66, "Scanning HTTP APIs…")
    if list(dx.find_methods(classname="Ljava/net/HttpURLConnection;")):
        insecure_apis.append("java.net.HttpURLConnection (Potential unencrypted traffic)")
    if list(dx.find_methods(classname="Ljava/net/URL;", methodname="openConnection")):
        insecure_apis.append("java.net.URL -> openConnection (Potential unencrypted traffic)")

    set_progress(task_id, 82, "Scoring…")
    score = len(risky_permissions)*2 + len(insecure_apis)*3
    max_score = 12*2 + 5*3  # heuristic

    result = {
        "file_type": "Android APK",
        "app_name": a.get_app_name(),
        "package": a.get_package(),
        "details_list": sorted(used_permissions),
        "risky_list": sorted(risky_permissions),
        "insecure_list": insecure_apis,
        "risk_score": int(score),
        "max_score": int(max_score),
        "risk_level": "High" if score > 10 else "Medium" if score > 5 else "Low",
        "headings": {
            "details": "🔐 Used Permissions",
            "risky": "🚨 Risky Permissions",
            "insecure": "🛡️ Insecure API Usage"
        }
    }
    set_progress(task_id, 88, "Finalizing…")
    return result

# --- EXE Analysis ---
def analyze_exe(exe_path, task_id):
    set_progress(task_id, 8, "Parsing EXE…")
    import pefile  # lazy import

    pe = pefile.PE(exe_path)
    set_progress(task_id, 24, "Hashing file…")
    with open(exe_path, 'rb') as f:
        data = f.read()
        sha = hashlib.sha256(data).hexdigest()

    set_progress(task_id, 48, "Analyzing imports…")
    risky_imports = set()
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                name = ""
                try:
                    name = imp.name.decode() if imp.name else ""
                except Exception:
                    pass
                if name in SUSPICIOUS_IMPORTS:
                    risky_imports.add(name)

    set_progress(task_id, 70, "Searching strings…")
    found_strings = set()
    for s in SUSPICIOUS_STRINGS:
        if s in data:
            try:
                found_strings.add(s.decode('utf-8', 'ignore'))
            except Exception:
                pass

    set_progress(task_id, 84, "Scoring…")
    score = len(risky_imports)*3 + len(found_strings)*1
    max_score = 10*3 + 8*1

    result = {
        "file_type": "Windows EXE",
        "app_name": os.path.basename(exe_path),
        "package": sha[:20] + "...",
        "details_list": [f"{s} (string found)" for s in sorted(found_strings)],
        "risky_list": sorted(risky_imports),
        "insecure_list": [],
        "risk_score": int(score),
        "max_score": int(max_score),
        "risk_level": "High" if score > 8 else "Medium" if score > 3 else "Low",
        "headings": {
            "details": "🔍 Suspicious Strings Found",
            "risky": "🚨 Suspicious Imported Functions",
            "insecure": " "
        }
    }
    set_progress(task_id, 90, "Finalizing…")
    return result

# --- Worker ---
def worker_scan(task_id, saved_path, filename, mode):
    try:
        set_progress(task_id, 3, "Starting scan…")
        if filename.lower().endswith(".apk"):
            if mode == "deep":
                result = analyze_apk_deep(saved_path, task_id)
            else:
                result = analyze_apk_fast(saved_path, task_id)
        elif filename.lower().endswith(".exe"):
            result = analyze_exe(saved_path, task_id)
        else:
            raise RuntimeError("Unsupported file type. Upload .apk or .exe")

        # Persist JSON
        report_filename = f"{os.path.basename(saved_path)}.json"
        report_path = os.path.join(REPORT_FOLDER, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        public_report_path = f"/reports/{report_filename}"
        set_progress(task_id, 100, "Done", result=result, report_path=public_report_path, done=True)
    except Exception as e:
        set_progress(task_id, 100, f"Failed: {e}", error=str(e), done=True)
    finally:
        try:
            if os.path.exists(saved_path):
                os.remove(saved_path)
        except Exception:
            pass

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "file" not in request.files:
            return abort(400, "No file part")
        f = request.files["file"]
        if f.filename == "":
            return abort(400, "No selected file")

        mode = request.form.get("mode", "fast")  # fast|deep
        filename = secure_filename(f.filename)
        saved_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{filename}")
        f.save(saved_path)

        task_id = init_task(mode)
        th = threading.Thread(target=worker_scan, args=(task_id, saved_path, filename, mode), daemon=True)
        th.start()

        return render_template("scan.html", task_id=task_id, mode=mode)
    return render_template("index.html")

@app.route("/progress/<task_id>")
def progress(task_id):
    with TASKS_LOCK:
        data = TASKS.get(task_id)
        if not data:
            return jsonify({"error":"Invalid task id"}), 404
        return jsonify({
            "progress": data.get("progress", 0),
            "status": data.get("status", "Working…"),
            "done": data.get("done", False),
            "error": data.get("error")
        })

@app.route("/result/<task_id>")
def result(task_id):
    with TASKS_LOCK:
        data = TASKS.get(task_id)
        if not data:
            return abort(404, "Invalid task id")
        res = data.get("result")
        err = data.get("error")
        report_path = data.get("report_path")
    return render_template("report.html", task_id=task_id, result=res, error=err, report_path=report_path)

@app.route("/reports/<path:name>")
def serve_report(name):
    safe = os.path.join(REPORT_FOLDER, os.path.basename(name))
    if not os.path.exists(safe):
        return abort(404)
    with open(safe, "rb") as f:
        content = f.read()
    return app.response_class(content, mimetype="application/json")

if __name__ == "__main__":
    app.run(debug=True)
