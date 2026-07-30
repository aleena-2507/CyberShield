from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)
from werkzeug.security import check_password_hash

from models import db, User, Incident, IncidentNote, Vulnerability

app = Flask(__name__)

# -------------------------
# APPLICATION CONFIGURATION
# -------------------------

app.config["SECRET_KEY"] = "cybershield-development-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cybershield.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# -------------------------
# DATABASE
# -------------------------

db.init_app(app)


# -------------------------
# LOGIN MANAGER
# -------------------------

login_manager = LoginManager()
login_manager.init_app(app)

# If someone tries to access a protected page,
# send them to the login page.
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# -------------------------
# LOGIN
# -------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    # Already logged in?
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):

            login_user(user)

            return redirect(url_for("dashboard"))

        flash("Invalid email address or password.", "error")

    return render_template("login.html")


# -------------------------
# DASHBOARD
# -------------------------
@app.route("/dashboard")
@login_required
def dashboard():

    # Total number of incidents
    total_incidents = Incident.query.count()

    # Incidents that still require attention
    active_incidents = Incident.query.filter(
        Incident.status.in_(["Open", "Investigating"])
    ).count()

    # Critical incidents
    critical_incidents = Incident.query.filter_by(
        severity="Critical"
    ).count()

    # Severity distribution
    critical_count = Incident.query.filter_by(
        severity="Critical"
    ).count()

    high_count = Incident.query.filter_by(
        severity="High"
    ).count()

    medium_count = Incident.query.filter_by(
        severity="Medium"
    ).count()

    low_count = Incident.query.filter_by(
        severity="Low"
    ).count()

    # Determine overall risk level
    if critical_count > 0:
        overall_risk = "CRITICAL"

    elif high_count > 0:
        overall_risk = "HIGH"

    elif medium_count > 0:
        overall_risk = "MEDIUM"

    else:
        overall_risk = "LOW"

    # Latest 5 incidents
    recent_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        user=current_user,
        total_incidents=total_incidents,
        active_incidents=active_incidents,
        critical_incidents=critical_incidents,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        overall_risk=overall_risk,
        recent_incidents=recent_incidents
    )
# -------------------------
# INCIDENT MANAGEMENT
# -------------------------

@app.route("/incidents")
@login_required
def incidents():

    all_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    return render_template(
        "incidents.html",
        incidents=all_incidents,
        user=current_user
    )


@app.route("/incidents/create", methods=["GET", "POST"])
@login_required
def create_incident():

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        affected_asset = request.form.get("affected_asset", "").strip()
        severity = request.form.get("severity", "").strip()

        allowed_severities = ["Low", "Medium", "High", "Critical"]

        if not title or not description or not affected_asset:
            flash("Please complete all required fields.", "error")
            return redirect(url_for("create_incident"))

        if severity not in allowed_severities:
            flash("Please select a valid severity.", "error")
            return redirect(url_for("create_incident"))

        incident = Incident(
            title=title,
            description=description,
            affected_asset=affected_asset,
            severity=severity,
            status="Open",
            created_by=current_user.id
        )

        db.session.add(incident)
        db.session.flush()

        incident.incident_id = (
            f"INC-{datetime.now().year}-{incident.id:03d}"
        )

        db.session.commit()

        flash(
            f"Incident {incident.incident_id} created successfully.",
            "success"
        )

        return redirect(url_for("incidents"))

    return render_template(
        "create_incident.html",
        user=current_user
    )

@app.route("/incidents/<int:id>")
@login_required
def incident_details(id):

    incident = db.get_or_404(Incident, id)

    notes = IncidentNote.query.filter_by(
        incident_id=incident.id
    ).order_by(
        IncidentNote.created_at.desc()
    ).all()

    return render_template(
        "incident_details.html",
        incident=incident,
        notes=notes,
        user=current_user
    )
@app.route("/incidents/<int:id>/status", methods=["POST"])
@login_required
def update_incident_status(id):

    incident = db.get_or_404(Incident, id)

    new_status = request.form.get("status")

    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved",
        "Closed"
    ]

    if new_status not in allowed_statuses:
        flash("Invalid incident status.", "error")

        return redirect(
            url_for("incident_details", id=id)
        )

    incident.status = new_status

    db.session.commit()

    flash(
        "Incident status updated successfully.",
        "success"
    )

    return redirect(
        url_for("incident_details", id=id)
    )
@app.route("/incidents/<int:id>/notes", methods=["POST"])
@login_required
def add_incident_note(id):

    incident = db.get_or_404(Incident, id)

    note_text = request.form.get("note", "").strip()

    if not note_text:

        flash(
            "Investigation note cannot be empty.",
            "error"
        )

        return redirect(
            url_for("incident_details", id=id)
        )

    note = IncidentNote(
        incident_id=incident.id,
        note=note_text,
        created_by=current_user.id
    )

    db.session.add(note)
    db.session.commit()

    flash(
        "Investigation note added.",
        "success"
    )

    return redirect(
        url_for("incident_details", id=id)
    )
# -------------------------
# VULNERABILITY MANAGEMENT
# -------------------------

@app.route("/vulnerabilities")
@login_required
def vulnerabilities():

    all_vulnerabilities = Vulnerability.query.order_by(
        Vulnerability.created_at.desc()
    ).all()

    return render_template(
        "vulnerabilities.html",
        vulnerabilities=all_vulnerabilities,
        user=current_user
    )


@app.route("/vulnerabilities/create", methods=["GET", "POST"])
@login_required
def create_vulnerability():

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        affected_asset = request.form.get("affected_asset", "").strip()
        cve_id = request.form.get("cve_id", "").strip()
        cvss_input = request.form.get("cvss_score", "").strip()
        description = request.form.get("description", "").strip()
        remediation = request.form.get("remediation", "").strip()

        # Required fields
        if (
            not title
            or not affected_asset
            or not cvss_input
            or not description
            or not remediation
        ):
            flash("Please complete all required fields.", "error")
            return redirect(url_for("create_vulnerability"))

        # Validate CVSS score
        try:
            cvss_score = float(cvss_input)
        except ValueError:
            flash("CVSS score must be a number.", "error")
            return redirect(url_for("create_vulnerability"))

        if cvss_score < 0 or cvss_score > 10:
            flash("CVSS score must be between 0 and 10.", "error")
            return redirect(url_for("create_vulnerability"))

        # Automatically calculate severity from CVSS
        if cvss_score >= 9.0:
            severity = "Critical"

        elif cvss_score >= 7.0:
            severity = "High"

        elif cvss_score >= 4.0:
            severity = "Medium"

        else:
            severity = "Low"

        vulnerability = Vulnerability(
            title=title,
            affected_asset=affected_asset,
            cve_id=cve_id if cve_id else None,
            cvss_score=cvss_score,
            severity=severity,
            description=description,
            remediation=remediation,
            status="Open",
            created_by=current_user.id
        )

        db.session.add(vulnerability)
        db.session.flush()

        vulnerability.vulnerability_id = (
            f"VUL-{datetime.now().year}-{vulnerability.id:03d}"
        )

        db.session.commit()

        flash(
            f"Vulnerability {vulnerability.vulnerability_id} created successfully.",
            "success"
        )

        return redirect(url_for("vulnerabilities"))

    return render_template(
        "create_vulnerability.html",
        user=current_user
    )
@app.route("/vulnerabilities/<int:id>")
@login_required
def vulnerability_details(id):

    vulnerability = db.get_or_404(Vulnerability, id)

    return render_template(
        "vulnerability_details.html",
        vulnerability=vulnerability,
        user=current_user
    )


@app.route("/vulnerabilities/<int:id>/status", methods=["POST"])
@login_required
def update_vulnerability_status(id):

    vulnerability = db.get_or_404(Vulnerability, id)

    new_status = request.form.get("status")

    allowed_statuses = [
        "Open",
        "In Progress",
        "Remediated",
        "Closed"
    ]

    if new_status not in allowed_statuses:
        flash("Invalid vulnerability status.", "error")
        return redirect(
            url_for("vulnerability_details", id=id)
        )

    vulnerability.status = new_status

    db.session.commit()

    flash(
        "Vulnerability status updated successfully.",
        "success"
    )

    return redirect(
        url_for("vulnerability_details", id=id)
    )
# -------------------------
# LOGOUT
# -------------------------

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))


# -------------------------
# START APPLICATION
# -------------------------

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)