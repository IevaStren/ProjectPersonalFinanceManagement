from flask import Blueprint, request, flash, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from flask_babel import _
from datetime import datetime, timedelta
import secrets
import re

from flask_mail import Message
from .models import User, GroupInvitation
from . import db, mail

auth = Blueprint('auth', __name__)


# function that validates password.
# Checks if empty, if pass not 8 characters long, if pass consists of 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character
def validate_password(password):
    if not password:
        return False, _("Password field is mandatory")
    if len(password) < 8:
        return False, _("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        return False, _("Password must contain an uppercase letter")
    if not re.search(r"[a-z]", password):
        return False, _("Password must contain a lowercase letter")
    if not re.search(r"[0-9]", password):
        return False, _("Password must contain at least 1 number")
    if not re.search(r"[^\w\s]", password):
        return False, _("Password must contain at least 1 special character")
    return True, ""

# function that validates e-mail
# Checks if empty, if email has '@' and '.' symbols
def validate_email(email):
    if len(email) < 1:
        return False, _("E-mail field is mandatory")
    if "@" not in email or "." not in email:
        return False, _("Invalid e-mail format. E-mail must contain symbols @ and .")
    return True, ""

# function that validates first_name
# Checks if empty
def validate_first_name(first_name):
    if first_name == "":
        return False, _("First name field is mandatory")
    return True, ""

# function that validates last_name
# Checks if empty
def validate_last_name(last_name):
    if last_name == "":
        return False, _("First name field is mandatory")
    return True, ""

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    # user sign_up request
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        print(len(password1))
        ok_password, msg_password = validate_password(password1)
        ok_email, msg_email = validate_email(email)
        ok_first_name, msg_first_name = validate_first_name(first_name)
        ok_last_name, msg_last_name = validate_last_name(last_name)

        # forms input validations
        if not password1:
            flash(_("Passwords field is empty"), "error")
        elif password1 != password2:
            flash(_("Passwords do not match"), "error")
        elif User.query.filter_by(email=email).first():
            flash(_("User with this email already exists"), "error")
        elif not ok_email:
            flash(msg_email, "error") 
        elif not ok_first_name:
            flash(msg_first_name, "error") 
        elif not ok_last_name:
            flash(msg_last_name, "error") 
        elif not ok_password:
            print(len(password1))
            flash(msg_password, "error") 
        #if all ok, creates and adds new user
        else:
            new_user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=generate_password_hash(password1)
            )
            db.session.add(new_user)
            db.session.commit()

            #logs in registered user in the system and redirects to dashboard view
            login_user(new_user)
            flash(_("Registration successful"), "success")
            return redirect(url_for('views.dashboard'))

    return render_template("sign_up.html", user=current_user)

# User login
@auth.route('/login', methods=['GET', 'POST'])
def login():

    invite_token = request.args.get("invite")
    email = request.form.get('email', '')

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        password = request.form.get('password')

        # If incorrect email returns error message
        if not user:
            flash(_("Invalid email or password"), "error")
            return redirect(url_for("auth.login"))

        # checks if user is active
        if not user.is_active:
            admin_user = User.query.filter_by(is_admin=True).first()
            admin_email = admin_user.email if admin_user else ""
            flash(_("Account is deactivated. Please contact administrator: %(email)s", email=admin_email), "error")
            return redirect(url_for("auth.login"))   

        if not check_password_hash(user.password, password):
            flash(_("Invalid email or password"), "error")
            return redirect(url_for("auth.login"))  

        # if validation ok, logs in user
        login_user(user, remember=True)

        # logs in user, that was invited in the system by the group invite
        if invite_token:
            invite = GroupInvitation.query.filter_by(token=invite_token, to_user_email=user.email, status="pending").first()
            if invite:
                user.group_budget_id = invite.group_id
                invite.status = "accepted"
                db.session.commit()

        return redirect(url_for('views.dashboard'))

    return render_template("login.html", email=email, user=current_user)

# passwords reset email
@auth.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()

        # if there is user with inputed email, ads reset token and expiry token to user.
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            link = url_for("auth.reset_password", token=token, _external=True)

            #Sends password reset message to the user
            msg = Message(subject=_("Password reset"), recipients=[user.email], body=_("To reset your password, open this link:") + f"\n{link}")
            mail.send(msg)

        flash(_("If the email exists, a reset link has been sent."), "success")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")

# Password reset
@auth.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    # checks if if password link is valid for the current user, and token has not expired
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash(_("The reset link is invalid or expired."), "error")
        return redirect(url_for("auth.login"))

    # password change request
    if request.method == "POST":
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        ok, msg = validate_password(password1)

        # new passwords validation
        if not ok:
            flash(msg, "error")
            return redirect(request.url)

        if password1 != password2:
            flash(_("Passwords do not match"), "error")
            return redirect(request.url)

        user.password = generate_password_hash(password1)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()

        flash(_("Password successfully changed"), "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html")

# Logout
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash(_("You have been logged out"), "success")
    return redirect(url_for('auth.login'))



