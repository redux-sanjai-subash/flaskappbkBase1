"""
Database models for HabitApp.

- User: stores accounts, password hash and helper methods.
- Habit: a habit belonging to a user.
- HabitLog: daily record for a habit (used to compute streaks/history).
"""

from . import db
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # one-to-many: a user has many habits
    habits = db.relationship("Habit", backref="user", cascade="all, delete-orphan", lazy="dynamic")

    def set_password(self, password: str) -> None:
        """Hash and store the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"

class Habit(db.Model):
    __tablename__ = "habits"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Example: daily, weekly, custom. Keep simple for now:
    frequency = db.Column(db.String(20), default="daily")

    # one-to-many: a habit has many logs
    logs = db.relationship("HabitLog", backref="habit", cascade="all, delete-orphan", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Habit id={self.id} user_id={self.user_id} name={self.name!r}>"

class HabitLog(db.Model):
    __tablename__ = "habit_logs"

    id = db.Column(db.Integer, primary_key=True)
    habit_id = db.Column(db.Integer, db.ForeignKey("habits.id"), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    done = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<HabitLog habit_id={self.habit_id} date={self.date} done={self.done}>"

