from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from database import db, Employee, Activity, Alert, SuspiciousPattern
from detection_engine import DetectionEngine
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "employee_monitoring.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'

db.init_app(app)
detection_engine = DetectionEngine(db.session)

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suspicious Employee Detection System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        h1 { color: #667eea; margin-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; }
        .stat-number { font-size: 36px; font-weight: bold; color: #667eea; }
        .card { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .card h2 { margin-bottom: 15px; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #333; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
        button:hover { background: #5a67d8; }
        .employee-item, .alert-item { padding: 10px; border: 1px solid #eee; margin-bottom: 10px; border-radius: 5px; display: flex; justify-content: space-between; align-items: center; }
        .risk-high { color: #ff4757; font-weight: bold; }
        .severity-critical { background: #ff4757; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
        .severity-high { background: #ffa502; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
        .row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .alert-success { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Suspicious Employee Detection System</h1>
            <p>Real-time employee monitoring and risk assessment</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="totalEmployees">0</div>
                <div class="stat-label">Total Employees</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="totalAlerts">0</div>
                <div class="stat-label">Active Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="criticalAlerts">0</div>
                <div class="stat-label">Critical Alerts</div>
            </div>
        </div>
        
        <div class="row">
            <div>
                <div class="card">
                    <h2>➕ Add New Employee</h2>
                    <div class="form-group">
                        <label>Employee ID</label>
                        <input type="text" id="empId" placeholder="EMP001">
                    </div>
                    <div class="form-group">
                        <label>Name</label>
                        <input type="text" id="empName" placeholder="John Doe">
                    </div>
                    <div class="form-group">
                        <label>Department</label>
                        <input type="text" id="empDept" placeholder="IT">
                    </div>
                    <button onclick="addEmployee()">Add Employee</button>
                </div>
                
                <div class="card">
                    <h2>📝 Record Activity</h2>
                    <div class="form-group">
                        <label>Select Employee</label>
                        <select id="activityEmployee"></select>
                    </div>
                    <div class="form-group">
                        <label>Activity Type</label>
                        <select id="activityType">
                            <option value="login">Login</option>
                            <option value="file_access">File Access</option>
                            <option value="data_export">Data Export</option>
                            <option value="failed_login">Failed Login</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" id="ipAddress" placeholder="192.168.1.100">
                    </div>
                    <button onclick="recordActivity()">Record Activity</button>
                    <div id="activityResult"></div>
                </div>
            </div>
            
            <div>
                <div class="card">
                    <h2>⚠️ Recent Alerts</h2>
                    <div id="alertsList"></div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>👥 High Risk Employees</h2>
            <div id="highRiskList"></div>
        </div>
    </div>
    
    <script>
        const API_BASE = 'http://localhost:5000/api';
        
        loadEmployees();
        loadAlerts();
        loadHighRisk();
        
        setInterval(() => {
            loadAlerts();
            loadHighRisk();
        }, 10000);
        
        async function loadEmployees() {
            const response = await fetch(`${API_BASE}/employees`);
            const employees = await response.json();
            const select = document.getElementById('activityEmployee');
            select.innerHTML = '<option value="">Select Employee</option>';
            employees.forEach(emp => {
                select.innerHTML += `<option value="${emp.id}">${emp.name}</option>`;
            });
            document.getElementById('totalEmployees').textContent = employees.length;
        }
        
        async function addEmployee() {
            const employee = {
                emp_id: document.getElementById('empId').value,
                name: document.getElementById('empName').value,
                department: document.getElementById('empDept').value,
                joining_date: new Date().toISOString().split('T')[0]
            };
            
            const response = await fetch(`${API_BASE}/employees`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(employee)
            });
            alert('Employee added!');
            loadEmployees();
        }
        
        async function recordActivity() {
            const employeeId = document.getElementById('activityEmployee').value;
            const activity = {
                employee_id: parseInt(employeeId),
                activity_type: document.getElementById('activityType').value,
                ip_address: document.getElementById('ipAddress').value || '127.0.0.1',
                details: 'Activity recorded'
            };
            
            const response = await fetch(`${API_BASE}/activities`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(activity)
            });
            const data = await response.json();
            document.getElementById('activityResult').innerHTML = `<div class="alert-success">✅ Risk Score: ${data.risk_score}%</div>`;
            loadAlerts();
            loadHighRisk();
        }
        
        async function loadAlerts() {
            const response = await fetch(`${API_BASE}/alerts`);
            const alerts = await response.json();
            const alertsList = document.getElementById('alertsList');
            alertsList.innerHTML = alerts.map(alert => `
                <div class="alert-item">
                    <div>
                        <strong>${alert.employee_name}</strong><br>
                        <span class="severity-${alert.severity}">${alert.severity.toUpperCase()}</span>
                        <p>${alert.description}</p>
                    </div>
                </div>
            `).join('');
            document.getElementById('totalAlerts').textContent = alerts.filter(a => !a.is_resolved).length;
            document.getElementById('criticalAlerts').textContent = alerts.filter(a => a.severity === 'critical' && !a.is_resolved).length;
        }
        
        async function loadHighRisk() {
            const response = await fetch(`${API_BASE}/analytics/dashboard`);
            const data = await response.json();
            const highRiskList = document.getElementById('highRiskList');
            highRiskList.innerHTML = data.high_risk_employees.map(emp => `
                <div class="employee-item">
                    <div>${emp.name} - ${emp.department}</div>
                    <div class="risk-high">${emp.risk_score}%</div>
                </div>
            `).join('');
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/employees', methods=['GET'])
def get_employees():
    employees = Employee.query.all()
    return jsonify([{'id': e.id, 'emp_id': e.emp_id, 'name': e.name, 'department': e.department} for e in employees])

@app.route('/api/employees', methods=['POST'])
def add_employee():
    data = request.json
    employee = Employee(
        emp_id=data['emp_id'],
        name=data['name'],
        department=data.get('department', ''),
        joining_date=datetime.strptime(data['joining_date'], '%Y-%m-%d').date()
    )
    db.session.add(employee)
    db.session.commit()
    return jsonify({'message': 'Employee added', 'id': employee.id})

@app.route('/api/activities', methods=['POST'])
def add_activity():
    data = request.json
    activity = Activity(
        employee_id=data['employee_id'],
        activity_type=data['activity_type'],
        ip_address=data.get('ip_address', ''),
        details=data.get('details', '')
    )
    db.session.add(activity)
    db.session.commit()
    
    employee = Employee.query.get(data['employee_id'])
    recent_activities = Activity.query.filter_by(employee_id=data['employee_id']).limit(100).all()
    risk_score, risk_factors = detection_engine.calculate_risk_score(data['employee_id'], recent_activities)
    alerts = detection_engine.generate_alert(employee, risk_score, risk_factors)
    
    for alert_data in alerts:
        alert = Alert(
            employee_id=data['employee_id'],
            alert_type=alert_data['type'],
            severity=alert_data['severity'],
            description=alert_data['description']
        )
        db.session.add(alert)
    
    db.session.commit()
    return jsonify({'risk_score': risk_score, 'alerts_generated': len(alerts)})

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([{
        'id': a.id,
        'employee_name': a.employee.name,
        'severity': a.severity,
        'description': a.description,
        'is_resolved': a.is_resolved
    } for a in alerts])

@app.route('/api/analytics/dashboard', methods=['GET'])
def get_dashboard_data():
    high_risk_employees = []
    for emp in Employee.query.all():
        activities = Activity.query.filter_by(employee_id=emp.id).limit(100).all()
        risk_score, _ = detection_engine.calculate_risk_score(emp.id, activities)
        if risk_score > 50:
            high_risk_employees.append({'name': emp.name, 'department': emp.department, 'risk_score': risk_score})
    return jsonify({'high_risk_employees': high_risk_employees})

with app.app_context():
    db.create_all()
    print("✅ Database created!")

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 Server running at: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)