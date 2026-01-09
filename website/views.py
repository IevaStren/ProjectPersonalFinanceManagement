from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort, session, current_app
from flask_login import login_required, current_user
from flask_babel import _
from datetime import datetime
from decimal import Decimal
import secrets
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Message
import re
import os
from . import db, mail
from .models import Expenses, Category, User, AuditLogs, GroupBudget, GroupInvitation
from . import db
from .auth import validate_password, validate_email, validate_last_name, validate_first_name

views = Blueprint('views', __name__)

# User expenses view and adds new expense
@views.route("/expenses", methods=["GET", "POST"])
@login_required
def expenses_view():
    #Selects all categories and orders them by name
    categories = Category.query.order_by(Category.name).all()
    query = Expenses.query.filter_by(user_id=current_user.id)

    #Adds new expense
    if request.method == "POST":
        # If user inputs ",", it is replaced by ".". If any exceptions are found, shows error message
        expense = Expenses(
            amount=Decimal(request.form["amount"].replace(",", ".")),
            category_id=int(request.form["category_id"]),
            expense_date=datetime.strptime(request.form["expense_date"], "%Y-%m-%d"),
            description=request.form.get("description"),
            user_id=current_user.id
        )
        
        db.session.add(expense)
        db.session.commit()

    expenses = query.order_by(Expenses.created_at.asc()).all()

    return render_template("expenses.html", expenses=expenses, categories=categories)


#Edit expense
@views.route('/expenses/<int:expense_id>', methods=['POST'])
@login_required
def edit_expense(expense_id):
    # if expense doesn't exist, error Not found
    expense = Expenses.query.get_or_404(expense_id)

    if expense.user_id != current_user.id:
        abort(403)

    # Edits expense
    expense.amount = Decimal(request.form['amount'].replace(",", "."))
    expense.category_id = int(request.form['category_id'])
    expense.expense_date = datetime.strptime(request.form['expense_date'], "%Y-%m-%d").date()
    expense.description = request.form.get('description')

    db.session.commit()
    flash(_("Expense updated"), "success")
    return redirect(url_for('views.expenses_view'))

# Deletes expense
@views.route('/expenses/<int:expense_id>/delete', methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Expenses.query.get_or_404(expense_id)

    if expense.user_id != current_user.id:
        abort(403)

    db.session.delete(expense)
    db.session.commit()

    return jsonify(success=True)


# checks if current user is authenticated and admin
def admin_required():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)

# If admin, Shows all users
@views.route("/admin/users")
@login_required
def admin_users():
    admin_required()
    users = User.query.all()
    return render_template("admin_users.html", users=users)


# Profile view
@views.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    # updates user profile
    if request.method == "POST":

        current_user.first_name = request.form.get("first_name", "").strip()
        current_user.last_name = request.form.get("last_name", "").strip()
        current_user.email = request.form.get("email", "").strip()
        old_password = request.form.get("old_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        #validation checks if user changes password. If ok, change password
        if old_password or new_password or confirm_password:
            if not old_password or not new_password or not confirm_password:
                flash(_("All password fields are required"), "error")
                return redirect(url_for("views.profile"))
            if not check_password_hash(current_user.password, old_password):
                flash(_("Old password is incorrect"), "error")
                return redirect(url_for("views.profile"))
            ok_pass, msg_pass = validate_password(new_password)
            if not ok_pass:
                flash(msg_pass, "error")
                return redirect(url_for("views.profile"))
            if new_password != confirm_password:
                flash(_("Passwords do not match"), "error")
                return redirect(url_for("views.profile"))
        
            current_user.password = generate_password_hash(new_password)
            
        db.session.commit()
        flash(_("Profile updated successfully"), "success")
        return redirect(url_for("views.profile"))

    return render_template("profile.html", user=current_user)

# Shows and edits users profile - Admin view
@views.route("/admin/user/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_user_profile(user_id):
    admin_required()

    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        user.first_name = request.form.get("first_name")
        user.last_name = request.form.get("first_name")
        user.email = request.form.get("email")

        if user.id != current_user.id:
            user.is_admin = "is_admin" in request.form
            user.is_active = "is_active" in request.form

        db.session.commit()
        flash(_("User updated successfully"), "success")

    return render_template(
        "profile.html",
        user=user,
        is_admin_view=True
    )

# Shows audit logs
@views.route("/admin/audit")
@login_required
def audit_logs():
    admin_required()

    logs = AuditLogs.query.order_by(AuditLogs.created_at.desc()).all()
    return render_template("admin_audit.html", logs=logs)

@views.route("/language/<lang>")
def set_language(lang):
    if lang not in ["en", "lv"]:
        return redirect(request.referrer or url_for("views.dashboard"))

    # Saves language in session
    session["lang"] = lang

    # If user is authenticated saves language in DB
    if current_user.is_authenticated:
        current_user.language = lang
        db.session.commit()

    return redirect(request.referrer or url_for("views.dashboard"))

# Shows categories and adds category
@views.route("/admin/categories", methods=["GET", "POST"])
@login_required
def admin_categories():
    if not current_user.is_admin:
        flash(_("You don't have access to this page"), "error")
        return redirect(url_for("views.dashboard"))

    if request.method == "POST":
        inputed_name = request.form.get("name")

        if inputed_name:
            exists = Category.query.filter_by(name=inputed_name).first()
            if not exists:
                db.session.add(Category(name=inputed_name))
                db.session.commit()
                flash(_("Category added"), "success")
            else:
                flash(_("Category already exists"), "error")

        return redirect(url_for("views.admin_categories"))

    categories = Category.query.all()

    return render_template(
        "admin_categories.html",
        categories=categories
    )

#Edit category name
@views.route("/admin/categories/<int:cat_id>", methods=["POST"])
@login_required
def edit_category(cat_id):
    if not current_user.is_admin:
        abort(403)

    category = Category.query.get_or_404(cat_id)
    category.name = request.form.get("name")

    db.session.commit()
    flash(_("Category updated"), "success")

    return redirect(url_for("views.admin_categories"))

#Delete category
@views.route("/admin/categories/<int:cat_id>/delete", methods=["POST"])
@login_required
def delete_category(cat_id):
    if not current_user.is_admin:
        abort(403)

    category = Category.query.get_or_404(cat_id)

    if category.expenses:
        flash(_("Category is used and cannot be deleted"), "error")
        return redirect(url_for("views.admin_categories"))

    db.session.delete(category)
    db.session.commit()

    flash(_("Category deleted"), "success")
    return redirect(url_for("views.admin_categories"))

#calculates this months range. Start is this months 1st date and end is next months 1st date
def month_range(dt: datetime):
    start = datetime(dt.year, dt.month, 1).date()
    if dt.month == 12:
        end = datetime(dt.year + 1, 1, 1).date()
    else:
        end = datetime(dt.year, dt.month + 1, 1).date()
    return start, end

#sends invitation email
def send_invite_email(email, token):
    #invitation link
    link = url_for("auth.login", _external=True) + f"?invite={token}"

    # Invitation Message to join group
    msg = Message(
        _("Group invitation"),
        sender=current_app.config["MAIL_USERNAME"],
        recipients=[email],
        body=f"""
You have been invited to join a group.

Click the link below to accept:
{link}

If you do not have an account, register first using this email.
"""
    )

    #sends message
    mail.send(msg)


# home page
@views.route("/")
@login_required
def dashboard():
    today = datetime.today()
    start, end = month_range(today)

    #selects all expenses that are in this months range
    personal_expenses = (Expenses.query.filter(
        Expenses.user_id == current_user.id,
        Expenses.expense_date >= start,
        Expenses.expense_date < end).all())

    #calculates income spent and balance
    personal_income = Decimal(current_user.monthly_income or 0)
    personal_spent = sum(Decimal(e.amount) for e in personal_expenses)
    personal_remaining = personal_income - personal_spent

    personal_chart = {}
    # for each expense gets categories and expense amount and adds them to personal chart
    for e in personal_expenses:
        name = e.category.name if e.category else _("Unknown")
        personal_chart[name] = personal_chart.get(name, Decimal("0")) + Decimal(e.amount)
        
    # selects all pending group invitations
    invitations = GroupInvitation.query.filter_by(
        to_user_email=current_user.email,
        status="pending"
    ).all()

    group = GroupBudget.query.get(current_user.group_budget_id) if current_user.group_budget_id else None

    return render_template(
        "dashboard.html",
        personal_income=personal_income,
        personal_spent=personal_spent,
        personal_remaining=personal_remaining,
        personal_chart={k: float(v) for k, v in personal_chart.items()},
        group=group,
        invitations=invitations
    )

# Function that change montly income
@views.route("/income", methods=["POST"])
@login_required
def update_montly_income():
    montly_income = request.form.get("monthly_income", "0")

    # If user inputs ",", it is replaced by ".". If any exceptions are found, shows error message
    try:
        current_user.monthly_income = Decimal(montly_income.replace(",", "."))
    except Exception:
        flash(_("Invalid income format"), "error")
        return redirect(url_for("views.dashboard"))
    
    # Checks if montly income is greater or equal to 0
    if Decimal(montly_income.replace(",", ".")) < 0:
        flash(_("Income must be greater or equal to 0"), "error")
        return redirect(url_for("views.dashboard"))

    # If validation passes, montly income is successfully updated
    db.session.commit()
    flash(_("Income updated successfully"), "success")
    return redirect(url_for("views.dashboard"))


# function to create group
@views.route("/group/create", methods=["POST"])
@login_required
def create_group():

    name = request.form.get("name")
    email = request.form.get("invite_email")

    group = GroupBudget(
        name=name,
        owner_id=current_user.id
    )
    db.session.add(group)
    db.session.commit()

    current_user.group_budget_id = group.id
    db.session.commit()

    if email:
        # generates url safe token
        token = secrets.token_urlsafe(32)

        invite = GroupInvitation(
            from_user_id=current_user.id,
            to_user_email=email,
            group_id=group.id,
            token=token
        )
        db.session.add(invite)
        db.session.commit()

        send_invite_email(email, token)

    flash(_("Group created"), "success")
    return redirect(url_for("views.dashboard"))

#Group overview 
@views.route("/group", methods=["GET"])
@login_required
def group_overview():
    invite_id = request.args.get("invite_id", type=int)

    invite = None
    # shows group invite
    if invite_id:
        invite = GroupInvitation.query.get_or_404(invite_id)
        if invite.to_user_email != current_user.email:
            abort(403)

    # if user is not in a group or doesn't have invite, then redirects to my overview
    if not current_user.group_budget_id and not invite:
        flash(_("You are not in a group"), "warning")
        return redirect(url_for("views.dashboard"))

    group_id = current_user.group_budget_id or (invite.group_id if invite else None)
    group = GroupBudget.query.get_or_404(group_id)

    today = datetime.today()
    start, end = month_range(today)

    members = User.query.filter_by(group_budget_id=group.id).all()

    per_user = []
    total_income = Decimal("0")
    total_spent = Decimal("0")
    group_chart = {}

    # for each member in the group, gets income, and expenses this month
    for u in members:
        income = Decimal(u.monthly_income or 0)

        user_expenses = (Expenses.query.filter(
                Expenses.user_id == u.id,
                Expenses.expense_date >= start,
                Expenses.expense_date < end).all())
        
        # sum and remainig money
        spent = sum(Decimal(e.amount) for e in user_expenses)
        remaining = income - spent

        user_chart = {}
        # for each expense gets category names and creates user and group charts
        for e in user_expenses:
            cname = e.category.name if e.category else _("Unknown")
            user_chart[cname] = user_chart.get(cname, Decimal("0")) + Decimal(e.amount)
            group_chart[cname] = group_chart.get(cname, Decimal("0")) + Decimal(e.amount)

        per_user.append({
            "user_id": u.id,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "email": u.email,
            "income": float(income),
            "spent": float(spent),
            "remaining": float(remaining),
            "chart": {k: float(v) for k, v in user_chart.items()}
        })

        #calculates groups total income and total spent and remaining
        total_income += income
        total_spent += spent

    total_remaining = total_income - total_spent

    return render_template(
        "group_overview.html",
        group=group,
        invite=invite,
        members=members,
        per_user=per_user,
        total_income=total_income,
        total_spent=total_spent,
        total_remaining=total_remaining,
        group_chart={k: float(v) for k, v in group_chart.items()},
        is_owner=(current_user.id == group.owner_id)
    )


# group member accepts invite
@views.route("/group/invite/<int:invite_id>/accept", methods=["POST"])
@login_required
def accept_invite(invite_id):
    invite = GroupInvitation.query.get_or_404(invite_id)
    if invite.to_user_email != current_user.email:
        abort(403)
    if invite.status != "pending":
        return redirect(url_for("views.dashboard"))

    current_user.group_budget_id = invite.group_id
    invite.status = "accepted"
    db.session.commit()

    flash(_("You joined the group"), "success")
    return redirect(url_for("views.group_overview"))

# group member declains invite
@views.route("/group/invite/<int:invite_id>/decline", methods=["POST"])
@login_required
def decline_invite(invite_id):
    invite = GroupInvitation.query.get_or_404(invite_id)
    if invite.to_user_email != current_user.email:
        abort(403)
    invite.status = "declined"
    db.session.commit()

    flash(_("Invitation declined"), "info")
    return redirect(url_for("views.dashboard"))


# Function to rename group
@views.route("/group/<int:group_id>/edit", methods=["POST"])
@login_required
def edit_group(group_id):
    group = GroupBudget.query.get_or_404(group_id)
    # checks if user is group owner
    if group.owner_id != current_user.id:
        abort(403)

    name = (request.form.get("name") or "").strip()
    if not name:
        flash(_("Group name is required"), "error")
        return redirect(url_for("views.group_overview"))

    group.name = name
    db.session.commit()
    flash(_("Group updated"), "success")
    return redirect(url_for("views.group_overview"))


# Function that deletes group 
@views.route("/group/<int:group_id>/delete", methods=["POST"])
@login_required
def delete_group(group_id):
    group = GroupBudget.query.get_or_404(group_id)
    #checks if user is group owner
    if group.owner_id != current_user.id:
        abort(403)

    # changes group members group_budget_id to None
    members = User.query.filter_by(group_budget_id=group.id).all()
    for u in members:
        u.group_budget_id = None

    # deletes group invitation
    GroupInvitation.query.filter_by(group_id=group.id).delete()

    db.session.delete(group)
    db.session.commit()

    flash(_("Group deleted"), "success")
    return redirect(url_for("views.dashboard"))


# Groups user can leave the group
@views.route("/group/leave", methods=["POST"])
@login_required
def leave_group():
    if not current_user.group_budget_id:
        return redirect(url_for("views.dashboard"))

    #group = GroupBudget.query.get(current_user.group_budget_id)
    #if group and group.owner_id == current_user.id:
    #   flash(_("Owner cannot leave the group. Delete it or transfer ownership."), "error")
    #   return redirect(url_for("views.group_overview"))

    current_user.group_budget_id = None
    db.session.commit()
    flash(_("You left the group"), "success")
    return redirect(url_for("views.dashboard"))


