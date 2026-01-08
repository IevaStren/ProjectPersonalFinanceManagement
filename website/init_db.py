from . import db
from .models import Category

DEFAULT_CATEGORIES = [
    "Food",
    "Groceries",
    "Transport",
    "Rent",
    "Utilities",
    "Entertainment",
    "Travel",
    "Wellbeing",
    "Household",
    "Health",
    "Pets",
    "Children",
    "Gifts",
    "Savings",
    "Other"
]

def define_categories():
    for name in DEFAULT_CATEGORIES:
        if not Category.query.filter_by(name=name).first():
            db.session.add(Category(name=name))
    db.session.commit()
