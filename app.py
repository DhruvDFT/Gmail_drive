import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session

# OPTIONAL: Try to import Google APIs (won't break if missing)
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    GOOGLE_APIS_AVAILABLE = True
except ImportError:
    GOOGLE_APIS_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-2024')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# MINIMAL Gmail scanner class
class BasicGmailScanner:
    def __init__(self):
        self.gmail_service = None
        self.credentials = None
        self.logs = []
        self.client_config = None
        
        # OAuth configuration
        self.SCOPES = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.metadata'
        ]
        
    def add_log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_entry)
        print(log_entry)

# Initialize scanner
scanner = BasicGmailScanner()

@app.route('/')
def index():
    """Working Railway deployment page"""
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔬 VLSI Resume Scanner</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh; padding: 20px; color: #333;
            }
            .container { 
                max-width: 900px; margin: 0 auto; 
                background: white; border-radius: 15px; 
                box-shadow: 0 20px 40px rgba(0,0,0,0.1); 
                overflow: hidden; 
            }
            .header {
                background: linear-gradient(135deg, #4a90e2 0%, #7b68ee 100%);
                color: white; padding: 30px; text-align: center;
            }
            .header h1 { font-size: 2.5em; margin-bottom: 10px; }
            .header p { font-size: 1.1em; opacity: 0.9; }
            .content { padding: 30px; }
            .status {
                background: #e8f5e8; border: 2px solid #4caf50;
                border-radius: 10px; padding: 20px; margin: 20px 0;
                text-align: center;
            }
            .auth-section {
                background: #f8f9fa; border-radius: 10px; 
                padding: 20px; margin-bottom: 30px; text-align: center;
            }
            .input-group {
                display: flex; gap: 10px; margin-bottom: 20px;
                justify-content: center; align-items: center; flex-wrap: wrap;
            }
            .input-group input {
                padding: 12px; border: 1px solid #ddd;
                border-radius: 5px; font-size: 1em; min-width: 250px;
            }
            .btn {
                padding: 12px 24px; background: #4a90e2; color: white;
                border: none; border-radius: 5px; cursor: pointer;
                font-size: 1em; margin: 5px;
            }
            .btn:hover { background: #357abd; }
            .btn-success { background: #28a745; }
            .btn-success:hover { background: #218838; }
            .hidden { display: none; }
            .main-content { display: none; }
            .debug {
                background: #f8f9fa; border: 1px solid #dee2e6;
                padding: 15px; border-radius: 5px; margin: 15px 0;
                font-family: monospace; font-size: 0.9em;
                max-height: 200px; overflow-y: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔬 VLSI Resume Scanner</h1>
                <p>Railway Deployment with GUI OAuth</p>
            </div>
            
            <div class="content">
                <div class="status">
                    <h3>✅ Railway Deployment Active!</h3>
                    <p>Application ready with GUI-based OAuth</p>
                </div>

                <div id="auth-section" class="auth-section">
                    <h3>🔐 Admin Authentication</h3>
                    <div class="input-group">
                        <input type="password" id="password" placeholder="Enter admin password">
                        <button onclick="login()">🔑 Login</button>
                    </div>
                    <p>Default password: <strong>admin123</strong></p>
                    <div class="debug" id="debug">
                        Ready to authenticate...
                    </div>
                </div>

                <div id="main-content" class="main-content">
                    <h2>🎛️ Gmail Scanner Dashboard</h2>
                    <p>Welcome! You are successfully authenticated.</p>
                    
                    <div class="auth-section">
                        <h4>📧 Gmail OAuth Setup</h4>
                        <p>Coming soon: Gmail OAuth configuration</p>
                        <button class="btn btn-success">🚀 Setup Gmail</button>
                    </div>
                    
                    <div class="auth-section">
                        <h4>📊 System Status</h4>
                        <div id="system-info">Loading...</div>
                        <button onclick="refreshInfo()">🔄 Refresh</button>
                    </div>
                    
                    <div class="auth-section">
                        <h4>📋 Activity Logs</h4>
                        <div class="debug" id="logs">Loading logs...</div>
                        <button onclick="refreshLogs()">🔄 Refresh Logs</button>
                    </div>
                </div>
            </div>
        </div>

        <script>
            function log(message) {
                const debugDiv = document.getElementById('debug');
                const timestamp = new Date().toLocaleTimeString();
                debugDiv.innerHTML += `[${timestamp}] ${message}<br>`;
                debugDiv.scrollTop = debugDiv.scrollHeight;
                console.log(message);
            }

            function login() {
                log("🔄 Starting login...");
                
                const password = document.getElementById('password').value;
                log(`📝 Password entered (length: ${password.length})`);
                
                if (!password) {
                    alert('Please enter admin password');
                    log("❌ No password entered");
                    return;
                }
                
                log("📡 Sending authentication request...");
                
                fetch('/api/auth', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password: password })
                })
                .then(response => {
                    log(`📡 Response status: ${response.status}`);
                    return response.json();
                })
                .then(data => {
                    log(`📥 Response: ${JSON.stringify(data)}`);
                    
                    if (data.success) {
                        log("✅ Authentication successful!");
                        document.getElementById('auth-section').style.display = 'none';
                        document.getElementById('main-content').style.display = 'block';
                        refreshInfo();
                        refreshLogs();
                    } else {
                        log(`❌ Authentication failed: ${data.message}`);
                        alert('Authentication failed: ' + data.message);
                        document.getElementById('password').value = '';
                    }
                })
                .catch(error => {
                    log(`❌ Request failed: ${error.message}`);
                    alert('Login failed: ' + error.message);
                });
            }

            function refreshInfo() {
                log("🔄 Refreshing system info...");
                
                fetch('/api/system-info')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('system-info').innerHTML = `
                        <p><strong>Port:</strong> ${data.port}</p>
                        <p><strong>Environment:</strong> ${data.environment}</p>
                        <p><strong>Google APIs:</strong> ${data.google_apis_available ? '✅' : '❌'}</p>
                        <p><strong>Status:</strong> ${data.deployment_status}</p>
                    `;
                    log("✅ System info refreshed");
                })
                .catch(err => {
                    log(`❌ Failed to refresh system info: ${err.message}`);
                });
            }

            function refreshLogs() {
                log("🔄 Refreshing logs...");
                
                fetch('/api/logs')
                .then(r => r.json())
                .then(data => {
                    if (data.logs && data.logs.length > 0) {
                        document.getElementById('logs').innerHTML = data.logs.slice(-10).join('<br>');
                    }
                    log("✅ Logs refreshed");
                })
                .catch(err => {
                    log(`❌ Failed to refresh logs: ${err.message}`);
                });
            }

            // Handle Enter key
            document.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && document.getElementById('auth-section').style.display !== 'none') {
                    login();
                }
            });

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                log("🚀 Page loaded successfully");
                log("🔧 Admin password: admin123");
            });
        </script>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/api/auth', methods=['POST'])
def api_auth():
    """Simple working authentication"""
    try:
        print(f"=== AUTH REQUEST at {datetime.now()} ===")
        
        data = request.get_json()
        print(f"Request data: {data}")
        
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        
        password = data.get('password', '')
        print(f"Password: '{password}' vs Expected: '{ADMIN_PASSWORD}'")
        
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            scanner.add_log("Admin authentication successful")
            print("✅ Authentication successful")
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            scanner.add_log("Failed admin authentication attempt", "WARNING")
            print("❌ Authentication failed")
            return jsonify({'success': False, 'message': 'Invalid password'})
            
    except Exception as e:
        print(f"❌ Auth error: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/system-info')
def api_system_info():
    """System information"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        return jsonify({
            'port': os.environ.get('PORT', 'Not Set'),
            'environment': 'Railway',
            'admin_authenticated': True,
            'google_apis_available': GOOGLE_APIS_AVAILABLE,
            'deployment_status': 'Active',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def api_logs():
    """Get activity logs"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        return jsonify({'logs': scanner.logs[-15:]})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/test')
def api_test():
    """API test endpoint"""
    return jsonify({
        'status': 'success',
        'message': 'API is working',
        'timestamp': datetime.now().isoformat(),
        'admin_password': ADMIN_PASSWORD
    })

@app.route('/health')
def health_check():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'VLSI Resume Scanner is running',
        'gmail_apis': GOOGLE_APIS_AVAILABLE
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# RAILWAY DEPLOYMENT ENTRY POINT
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    print(f"🚀 Starting VLSI Resume Scanner on Railway")
    print(f"📊 Port: {port}")
    print(f"🔑 Admin password: '{ADMIN_PASSWORD}'")
    print(f"📧 Google APIs Available: {GOOGLE_APIS_AVAILABLE}")
    
    scanner.add_log("Application starting up")
    
    app.run(
        debug=debug_mode, 
        host='0.0.0.0', 
        port=port
    )
