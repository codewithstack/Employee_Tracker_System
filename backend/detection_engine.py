from datetime import datetime

class DetectionEngine:
    
    def __init__(self, db_session):
        self.db = db_session
        
    def calculate_risk_score(self, employee_id, activities):
        """Calculate overall risk score for an employee"""
        risk_factors = {
            'unusual_hours': self.check_unusual_hours(activities),
            'excessive_access': self.check_excessive_access(activities),
            'data_export': self.check_data_export_patterns(activities),
            'multiple_locations': self.check_multiple_locations(activities),
            'failed_attempts': self.check_failed_attempts(activities),
            'off_hours_access': self.check_off_hours_access(activities)
        }
        
        total_score = sum(risk_factors.values())
        return min(total_score, 100.0), risk_factors
    
    def check_unusual_hours(self, activities):
        unusual_count = 0
        for activity in activities:
            hour = activity.timestamp.hour
            if hour >= 23 or hour <= 5:
                unusual_count += 1
        
        if unusual_count > 10:
            return 25
        elif unusual_count > 5:
            return 15
        elif unusual_count > 2:
            return 8
        return 0
    
    def check_excessive_access(self, activities):
        access_count = len([a for a in activities if a.activity_type in ['file_access', 'data_view']])
        
        if access_count > 100:
            return 20
        elif access_count > 50:
            return 12
        elif access_count > 30:
            return 6
        return 0
    
    def check_data_export_patterns(self, activities):
        exports = [a for a in activities if a.activity_type == 'data_export']
        
        if len(exports) > 5:
            return 30
        elif len(exports) > 3:
            return 20
        elif len(exports) > 1:
            return 10
        return 0
    
    def check_multiple_locations(self, activities):
        locations = set()
        for activity in activities:
            if activity.activity_type == 'login' and activity.ip_address:
                locations.add(activity.ip_address)
        
        if len(locations) > 3:
            return 20
        elif len(locations) > 2:
            return 10
        return 0
    
    def check_failed_attempts(self, activities):
        failed = [a for a in activities if 'failed' in a.details.lower()]
        
        if len(failed) > 10:
            return 20
        elif len(failed) > 5:
            return 12
        elif len(failed) > 2:
            return 5
        return 0
    
    def check_off_hours_access(self, activities):
        weekend_count = 0
        for activity in activities:
            if activity.timestamp.weekday() >= 5:
                weekend_count += 1
        
        if weekend_count > 15:
            return 15
        elif weekend_count > 8:
            return 10
        elif weekend_count > 3:
            return 5
        return 0
    
    def generate_alert(self, employee, risk_score, risk_factors):
        alerts = []
        
        if risk_score >= 80:
            alerts.append({
                'type': 'critical_risk',
                'severity': 'critical',
                'description': f'Employee {employee.name} has critical risk score of {risk_score:.1f}'
            })
        elif risk_score >= 60:
            alerts.append({
                'type': 'high_risk',
                'severity': 'high',
                'description': f'Employee {employee.name} has high risk score of {risk_score:.1f}'
            })
        
        if risk_factors['data_export'] > 15:
            alerts.append({
                'type': 'data_breach',
                'severity': 'critical',
                'description': f'Unusual data export activity detected for {employee.name}'
            })
        
        if risk_factors['multiple_locations'] > 10:
            alerts.append({
                'type': 'suspicious_login',
                'severity': 'high',
                'description': f'Multiple location logins detected for {employee.name}'
            })
        
        return alerts