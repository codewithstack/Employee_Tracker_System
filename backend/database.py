from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Employee(db.Model):
    __tablename__ = 'employees'
    
    id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50))
    designation = db.Column(db.String(50))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    joining_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)
    
    activities = db.relationship('Activity', backref='employee', lazy=True)
    alerts = db.relationship('Alert', backref='employee', lazy=True)

class Activity(db.Model):
    __tablename__ = 'activities'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    activity_type = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    device_info = db.Column(db.String(200))
    details = db.Column(db.Text)
    risk_score = db.Column(db.Float, default=0.0)

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    alert_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_by = db.Column(db.String(100))
    resolved_at = db.Column(db.DateTime)

class SuspiciousPattern(db.Model):
    __tablename__ = 'suspicious_patterns'
    
    id = db.Column(db.Integer, primary_key=True)
    pattern_name = db.Column(db.String(100))
    threshold = db.Column(db.Float)
    weight = db.Column(db.Float)
    is_active = db.Column(db.Boolean, default=True)