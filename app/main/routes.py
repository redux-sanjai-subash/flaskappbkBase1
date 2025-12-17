from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from .. import db
from ..models import User, Domain, Project, ManualDomain
from ..utils import fetch_ssl_details
from .forms import SignupForm, LoginForm, ProfileForm, ChangePasswordForm, DomainFilterForm, DomainSearchForm
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, date

main_bp = Blueprint("main", __name__, template_folder="templates")

def compute_status(days_left):
    """
    Returns a string status based on days left:
    - Expired: days_left < 0
    - Expiring Soon: 0 <= days_left <= 30
    - Active: days_left > 30
    - Unknown: days_left is None
    """
    if days_left is None:
        return "Unknown"
    elif days_left < 0:
        return "Expired"
    elif days_left <= 30:
        return "Expiring Soon"
    else:
        return "Active"


# ---------------------------
# Authentication routes
# ---------------------------
@main_bp.route('/')
def index():
    return redirect(url_for("main.login"))


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in successfully!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("main.dashboard"))
        else:
            flash("Invalid email or password", "danger")
    return render_template("main/login.html", form=form)


@main_bp.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("main.signup"))

        new_user = User(
            email=form.email.data,
            username=form.username.data or None,
        )
        new_user.set_password(form.password.data)

        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! You can now log in.", "success")
        return redirect(url_for("main.login"))

    return render_template("main/signup.html", form=form)


@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.login"))


# ---------------------------
# Dashboard
# ---------------------------
@main_bp.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    projects = Project.query.all()

    filter_form = DomainFilterForm()
    filter_form.project_id.choices = [(0, "All Projects")] + [(p.id, p.name) for p in projects]
    search_form = DomainSearchForm()

    all_domains = Domain.query.options(joinedload(Domain.project)).all()
    manual_domains = ManualDomain.query.options(joinedload(ManualDomain.project)).all()

    # Normalize ManualDomains
    normalized_manual_domains = []
    for m in manual_domains:
        normalized_manual_domains.append(type('DomainLike', (), {
            'id': m.id,
            'domain_name': m.domain_name,
            'project': m.project,
            'provider': m.provider,
            'ssl_expiry': m.ssl_expiry,
            'days_left': m.days_left,
            'manual_override': True,
            'status': compute_status(m.days_left)
        })())

    # Normalize Domains
    normalized_domains = []
    for d in all_domains:
        normalized_domains.append(type('DomainLike', (), {
            'id': d.id,
            'domain_name': d.domain_name,
            'project': d.project,
            'provider': d.provider,
            'ssl_expiry': d.ssl_expiry,
            'days_left': d.days_left,
            'manual_override': False,
            'status': compute_status(d.days_left)
        })())

    # Combine both
    domains = normalized_domains + normalized_manual_domains

    # Apply filters or search
    if request.method == "POST":
        if "filter" in request.form:
            selected_project = filter_form.project_id.data
            show_manual = filter_form.show_manual.data

            if selected_project and selected_project != 0:
                domains = [d for d in domains if d.project and d.project.id == selected_project]

            if show_manual:
                domains = [d for d in domains if d.manual_override]

        elif "search" in request.form:
            search_term = search_form.search_query.data.strip().lower()
            if search_term:
                domains = [
                    d for d in domains
                    if (search_term in d.domain_name.lower())
                    or (d.project and search_term in d.project.name.lower())
                    or (d.provider and search_term in d.provider.lower())
                ]

    domains.sort(key=lambda d: (d.days_left if d.days_left is not None else float('inf')))

    return render_template(
        "main/dashboard.html",
        domains=domains,
        filter_form=filter_form,
        search_form=search_form,
    )


# ---------------------------
# Domain CRUD routes
# ---------------------------
@main_bp.route("/domain/add", methods=["GET", "POST"])
@login_required
def add_domain():
    projects = Project.query.all()
    if request.method == "POST":
        domain_name = request.form.get("domain_name").strip()
        project_id = request.form.get("project_id")
        manual_override = bool(request.form.get("manual_override"))

        # Check duplicates
        if Domain.query.filter_by(domain_name=domain_name).first() or ManualDomain.query.filter_by(domain_name=domain_name).first():
            flash("Domain already exists.", "danger")
            return redirect(url_for("main.add_domain"))

        if manual_override:
            expiry_str = request.form.get("ssl_expiry")
            ssl_expiry = datetime.strptime(expiry_str, "%Y-%m-%d").date() if expiry_str else None

            manual_domain = ManualDomain(
                domain_name=domain_name,
                project_id=project_id or None,
                provider=request.form.get("provider"),
                ssl_expiry=ssl_expiry,
            )
            db.session.add(manual_domain)
        else:
            ssl_info = fetch_ssl_details(domain_name)
            provider = ssl_info["provider"] if ssl_info else None
            ssl_expiry = ssl_info["expiry"] if ssl_info else None

            domain = Domain(
                domain_name=domain_name,
                project_id=project_id or None,
                provider=provider,
                ssl_expiry=ssl_expiry,
            )
            db.session.add(domain)

        db.session.commit()
        flash("Domain added successfully.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("main/domain_add.html", projects=projects)

@main_bp.route("/domain/<string:domain_type>/<int:domain_id>/edit", methods=["GET", "POST"])
@login_required
def edit_domain(domain_type, domain_id):
    # --- Load domain explicitly based on type ---
    if domain_type == "auto":
        domain = Domain.query.get_or_404(domain_id)
        manual_domain = None
    elif domain_type == "manual":
        manual_domain = ManualDomain.query.get_or_404(domain_id)
        domain = None
    else:
        abort(404)

    projects = Project.query.all()

    if request.method == "POST":
        is_manual = bool(request.form.get("manual_override"))
        domain_name = request.form.get("domain_name").strip()
        project_id = request.form.get("project_id") or None

        # -------------------------
        # Switch to MANUAL domain
        # -------------------------
        if is_manual:
            provider = request.form.get("provider")
            expiry_str = request.form.get("ssl_expiry")
            ssl_expiry = (
                datetime.strptime(expiry_str, "%Y-%m-%d").date()
                if expiry_str else None
            )

            # auto → manual
            if domain:
                new_manual = ManualDomain(
                    domain_name=domain_name,
                    project_id=project_id,
                    provider=provider,
                    ssl_expiry=ssl_expiry,
                )
                db.session.delete(domain)
                db.session.add(new_manual)

            # manual → manual (edit)
            else:
                manual_domain.domain_name = domain_name
                manual_domain.project_id = project_id
                manual_domain.provider = provider
                manual_domain.ssl_expiry = ssl_expiry

        # -------------------------
        # Switch to AUTO domain
        # -------------------------
        else:
            ssl_info = fetch_ssl_details(domain_name)
            provider = ssl_info["provider"] if ssl_info else None
            ssl_expiry = ssl_info["expiry"] if ssl_info else None

            # manual → auto
            if manual_domain:
                new_domain = Domain(
                    domain_name=domain_name,
                    project_id=project_id,
                    provider=provider,
                    ssl_expiry=ssl_expiry,
                )
                db.session.delete(manual_domain)
                db.session.add(new_domain)

            # auto → auto (edit)
            else:
                domain.domain_name = domain_name
                domain.project_id = project_id
                domain.provider = provider
                domain.ssl_expiry = ssl_expiry

        db.session.commit()
        flash("Domain updated successfully.", "success")
        return redirect(url_for("main.dashboard"))

    # --- Correct object passed to template ---
    current_data = manual_domain if domain_type == "manual" else domain
    return render_template(
        "main/domain_edit.html",
        domain=current_data,
        projects=projects,
        domain_type=domain_type,
    )



@main_bp.route("/domain/<int:domain_id>/delete", methods=["POST"])
@login_required
def delete_domain(domain_id):
    domain = Domain.query.get(domain_id)
    manual_domain = ManualDomain.query.get(domain_id)

    if not domain and not manual_domain:
        abort(404)

    db.session.delete(domain or manual_domain)
    db.session.commit()
    flash("Domain deleted successfully.", "success")
    return redirect(url_for("main.dashboard"))

# ---------------------------
# User Settings
# ---------------------------
@main_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    profile_form = ProfileForm(obj=current_user)
    pwd_form = ChangePasswordForm()

    # Profile update
    if "submit_profile" in request.form and profile_form.validate_on_submit():
        new_email = profile_form.email.data.strip().lower()
        new_username = profile_form.username.data.strip() if profile_form.username.data else None

        existing = User.query.filter_by(email=new_email).first()
        if existing and existing.id != current_user.id:
            flash("That email is already in use by another account.", "danger")
            return redirect(url_for("main.settings"))

        if new_username:
            u = User.query.filter_by(username=new_username).first()
            if u and u.id != current_user.id:
                flash("That username is already taken.", "danger")
                return redirect(url_for("main.settings"))

        current_user.email = new_email
        current_user.username = new_username
        try:
            db.session.commit()
            flash("Profile updated successfully.", "success")
        except IntegrityError:
            db.session.rollback()
            flash("Unable to update profile. Please try again.", "danger")
        return redirect(url_for("main.settings"))

    # Password change
    if "submit_password" in request.form and pwd_form.validate_on_submit():
        if not current_user.check_password(pwd_form.current_password.data):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("main.settings"))

        current_user.set_password(pwd_form.new_password.data)
        db.session.commit()
        flash("Password changed successfully.", "success")
        return redirect(url_for("main.settings"))

    return render_template("main/settings.html", profile_form=profile_form, pwd_form=pwd_form)
