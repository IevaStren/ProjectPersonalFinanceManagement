from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from datetime import datetime

class GroupBudget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=func.now(),onupdate=func.now())
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    users = db.relationship("User",back_populates="group_budget",foreign_keys="User.group_budget_id")
    owner = db.relationship("User",foreign_keys=[owner_id],backref="owned_groups")

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(),onupdate=func.now())

    expenses = db.relationship("Expenses", backref="category", lazy="select")


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    language = db.Column(db.String(50), default="en")
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(),onupdate=func.now())
    monthly_income = db.Column(db.Numeric(10, 2), default=0)
    group_budget_id = db.Column(db.Integer,db.ForeignKey('group_budget.id'),nullable=True)

    expenses = db.relationship("Expenses", backref="user")
    group_budget = db.relationship("GroupBudget",back_populates="users",foreign_keys=[group_budget_id])


class Expenses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    expense_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(),onupdate=func.now())
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

class AuditLogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    details = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class GroupInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    to_user_email = db.Column(db.String(150))
    token = db.Column(db.String(64), unique=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group_budget.id"))
    status = db.Column(db.String(20), default="pending")  # pending / accepted / declined
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=func.now(),onupdate=func.now())


