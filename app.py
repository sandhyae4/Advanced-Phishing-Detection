from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from config import SECRET_KEY, DATABASE, MODEL_PATH
from services.database import init_db, save_scan, get_scan, dashboard_data
from services.analyzer import analyze_url
from services.model_service import ensure_model
from services.report import build_pdf


def create_app():
    app = Flask(__name__)
    app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=16 * 1024)
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    init_db()
    ensure_model()

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/analyze")
    def analyze():
        raw_url = request.form.get("url", "").strip()
        try:
            result = analyze_url(raw_url)
            result["id"] = save_scan(result)
            return render_template("result.html", result=result)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("index"))

    @app.post("/api/analyze")
    def api_analyze():
        payload = request.get_json(silent=True) or {}
        try:
            result = analyze_url(str(payload.get("url", "")).strip())
            result["id"] = save_scan(result)
            return jsonify(result), 200
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html", data=dashboard_data())

    @app.get("/report/<int:scan_id>.pdf")
    def report(scan_id):
        scan = get_scan(scan_id)
        if not scan:
            return "Report not found", 404
        return send_file(build_pdf(scan), mimetype="application/pdf", as_attachment=True,
                         download_name=f"phishing-assessment-{scan_id}.pdf")

    @app.get("/health")
    def health():
        return jsonify({"status": "healthy"})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

