import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session

# OPTIONAL: Try to import Google APIs (won't break if missing)
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_APIS_AVAILABLE = True
except ImportError:
    GOOGLE_APIS_AVAILABLE = False

app = Flask(__name__)

# RAILWAY DEPLOYMENT LOGIC - CORE ESSENTIALS (UNCHANGED)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-2024')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# MINIMAL Gmail scanner class
class BasicGmailScanner:
    def __init__(self):
        self.gmail_service = None
        self.credentials = None
        self.logs = []
        
    def add_log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.logs.append(f"[{timestamp}] {message}")
        print(f"[{timestamp}] {message}")  # Railway logs
        
    def start_oauth(self):
        """Start OAuth - BASIC version"""
        try:
            if not GOOGLE_APIS_AVAILABLE:
                return {'success': False, 'error': 'Google APIs not installed'}
                
            client_id = os.environ.get('GOOGLE_CLIENT_ID')
            client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
            
            if not client_id or not client_secret:
                return {'success': False, 'error': 'Google credentials not configured in Railway environment'}
            
            # Basic OAuth URL generation
            import urllib.parse
            params = {
                'client_id': client_id,
                'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
                'scope': 'https://www.googleapis.com/auth/gmail.readonly',
                'response_type': 'code',
                'access_type': 'offline'
            }
            
            auth_url = 'https://accounts.google.com/o/oauth2/auth?' + urllib.parse.urlencode(params)
            
            # Store for later
            session['oauth_client_id'] = client_id
            session['oauth_client_secret'] = client_secret
            
            self.add_log("OAuth URL generated successfully")
            return {'success': True, 'auth_url': auth_url}
            
        except Exception as e:
            self.add_log(f"OAuth start failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def complete_oauth(self, auth_code):
        """Complete OAuth - BASIC version"""
        try:
            client_id = session.get('oauth_client_id')
            client_secret = session.get('oauth_client_secret')
            
            if not client_id or not client_secret:
                return {'success': False, 'error': 'OAuth session lost'}
            
            # Manual token exchange
            import urllib.parse, urllib.request, json
            
            token_data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'code': auth_code,
                'grant_type': 'authorization_code',
                'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob'
            }
            
            req = urllib.request.Request(
                'https://oauth2.googleapis.com/token',
                data=urllib.parse.urlencode(token_data).encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            with urllib.request.urlopen(req) as response:
                token_response = json.loads(response.read().decode())
            
            # Create credentials
            self.credentials = Credentials(
                token=token_response.get('access_token'),
                refresh_token=token_response.get('refresh_token'),
                token_uri='https://oauth2.googleapis.com/token',
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Test Gmail connection
            self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
            profile = self.gmail_service.users().getProfile(userId='me').execute()
            email = profile.get('emailAddress', 'Unknown')
            
            self.add_log(f"Gmail authentication successful for: {email}")
            return {'success': True, 'email': email}
            
        except Exception as e:
            self.add_log(f"OAuth completion failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def basic_gmail_scan(self, max_emails=100):
        """BASIC Gmail scan - just count emails"""
        try:
            if not self.gmail_service:
                return {'success': False, 'error': 'Gmail not authenticated'}
            
            self.add_log(f"Starting basic Gmail scan (max {max_emails} emails)")
            
            # Simple query
            query = 'subject:resume OR subject:CV'
            
            # Get email list
            results = self.gmail_service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_emails
            ).execute()
            
            messages = results.get('messages', [])
            count = len(messages)
            
            self.add_log(f"Basic scan completed: Found {count} emails")
            
            return {
                'success': True,
                'emails_found': count,
                'query_used': query,
                'method': 'basic_gmail_list'
            }
            
        except Exception as e:
            self.add_log(f"Gmail scan failed: {e}")
            return {'success': False, 'error': str(e)}

# Initialize scanner
scanner = BasicGmailScanner()

@app.route('/')
def index():
    """Railway deployment confirmation page - ENHANCED with Gmail"""
    # Check if credentials are configured via Railway environment
    has_credentials = (
        bool(os.environ.get('GOOGLE_CLIENT_ID')) and 
        bool(os.environ.get('GOOGLE_CLIENT_SECRET'))
    )
    
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔬 VLSI Resume Scanner - Railway</title>
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
            .auth-section, .gmail-section {
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
            .env-status {
                background: #fff3cd; border: 1px solid #ffeaa7;
                border-radius: 10px; padding: 15px; margin: 15px 0;
            }
            .oauth-section {
                background: #e3f2fd; border: 1px solid #2196f3;
                border-radius: 10px; padding: 15px; margin: 15px 0;
            }
            .oauth-url {
                background: #f5f5f5; padding: 10px; border-radius: 5px;
                word-break: break-all; margin: 10px 0; font-size: 0.9em;
            }
            .logs {
                background: #f1f1f1; padding: 10px; border-radius: 5px;
                max-height: 200px; overflow-y: auto; font-family: monospace;
                font-size: 0.9em; text-align: left;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔬 VLSI Resume Scanner</h1>
                <p>Railway Deployment + Basic Gmail Scanner</p>
            </div>
            
            <div class="content">
                <div class="status">
                    <h3>✅ Railway Deployment Successful!</h3>
                    <p>Application with basic Gmail functionality is running</p>
                </div>

                <div class="env-status">
                    <h4>🔧 Environment Configuration</h4>
                    <p><strong>Port:</strong> ''' + str(os.environ.get('PORT', 'Not Set')) + '''</p>
                    <p><strong>Google APIs:</strong> ''' + ('✅ Available' if GOOGLE_APIS_AVAILABLE else '❌ Not Installed') + '''</p>
                    <p><strong>Google Client ID:</strong> ''' + ('✅ Configured' if os.environ.get('GOOGLE_CLIENT_ID') else '❌ Not Set') + '''</p>
                    <p><strong>Google Client Secret:</strong> ''' + ('✅ Configured' if os.environ.get('GOOGLE_CLIENT_SECRET') else '❌ Not Set') + '''</p>
                    <p><strong>Admin Password:</strong> ''' + ('✅ Custom' if os.environ.get('ADMIN_PASSWORD') else '⚠️ Default (admin123)') + '''</p>
                </div>

                <div id="auth-section" class="auth-section">
                    <h3>🔐 Admin Authentication</h3>
                    <div class="input-group">
                        <input type="password" id="admin-password" placeholder="Enter admin password">
                        <button class="btn" onclick="authenticate()">🔑 Login</button>
                    </div>
                    <p>Enter admin password to access the Gmail scanner</p>
                </div>

                <div id="main-content" class="main-content">
                    <h2>🎛️ Basic Gmail Scanner</h2>
                    <p>Railway deployment successful. Ready for basic Gmail scanning.</p>
                    
                    <div class="gmail-section">
                        <h4>📧 Gmail Authentication</h4>
                        <button class="btn btn-success" onclick="startOAuth()" id="oauth-btn">🚀 Start Gmail OAuth</button>
                        
                        <div id="oauth-section" class="oauth-section hidden">
                            <h5>📋 OAuth Authorization</h5>
                            <p>1. Click the link below to authorize:</p>
                            <div id="auth-url" class="oauth-url"></div>
                            <p>2. Enter the authorization code:</p>
                            <div class="input-group">
                                <input type="text" id="auth-code" placeholder="Paste authorization code">
                                <button class="btn" onclick="completeOAuth()">✅ Complete</button>
                            </div>
                        </div>
                        
                        <button class="btn" onclick="basicGmailScan()" id="scan-btn" disabled>📊 Basic Gmail Scan (100 emails)</button>
                        <div id="scan-results"></div>
                    </div>
                    
                    <div class="auth-section">
                        <h4>📊 System Information</h4>
                        <div id="system-info">
                            <p>Loading system information...</p>
                        </div>
                        <button class="btn" onclick="refreshSystemInfo()">🔄 Refresh Info</button>
                    </div>
                    
                    <div class="auth-section">
                        <h4>📋 Activity Logs</h4>
                        <div id="logs" class="logs">
                            <p>Logs will appear here...</p>
                        </div>
                        <button class="btn" onclick="refreshLogs()">🔄 Refresh Logs</button>
                    </div>
                </div>
            </div>
        </div>

        <script>
        function authenticate() {
            const password = document.getElementById('admin-password').value;
            
            if (!password) {
                alert('Please enter admin password');
                return;
            }
            
            fetch('/api/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: password })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('auth-section').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                    refreshSystemInfo();
                    refreshLogs();
                } else {
                    alert('Invalid password. Please try again.');
                    document.getElementById('admin-password').value = '';
                }
            })
            .catch(err => {
                alert('Authentication failed. Please try again.');
                console.error('Auth error:', err);
            });
        }

        function startOAuth() {
            fetch('/api/gmail/start-oauth', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('oauth-section').classList.remove('hidden');
                    document.getElementById('auth-url').innerHTML = 
                        `<a href="${data.auth_url}" target="_blank">${data.auth_url}</a>`;
                    document.getElementById('oauth-btn').textContent = '⏳ Waiting...';
                    document.getElementById('oauth-btn').disabled = true;
                } else {
                    alert('OAuth start failed: ' + data.error);
                }
            })
            .catch(err => {
                alert('OAuth request failed');
                console.error('OAuth error:', err);
            });
        }

        function completeOAuth() {
            const authCode = document.getElementById('auth-code').value;
            if (!authCode) {
                alert('Please enter authorization code');
                return;
            }
            
            fetch('/api/gmail/complete-oauth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ auth_code: authCode })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('Gmail authentication successful! Email: ' + data.email);
                    document.getElementById('oauth-section').classList.add('hidden');
                    document.getElementById('oauth-btn').textContent = '✅ Gmail Connected';
                    document.getElementById('scan-btn').disabled = false;
                    refreshLogs();
                } else {
                    alert('OAuth completion failed: ' + data.error);
                }
            })
            .catch(err => {
                alert('OAuth completion failed');
                console.error('OAuth error:', err);
            });
        }

        function basicGmailScan() {
            document.getElementById('scan-results').innerHTML = '<p>🔄 Scanning Gmail for resume emails...</p>';
            
            fetch('/api/gmail/basic-scan', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('scan-results').innerHTML = 
                        `<p>✅ Basic scan completed! Found ${data.emails_found} emails with resume/CV keywords.</p>
                         <p><small>Query: ${data.query_used}</small></p>`;
                } else {
                    document.getElementById('scan-results').innerHTML = 
                        `<p style="color: red;">❌ Scan failed: ${data.error}</p>`;
                }
                refreshLogs();
            })
            .catch(err => {
                document.getElementById('scan-results').innerHTML = 
                    '<p style="color: red;">❌ Scan request failed</p>';
                console.error('Scan error:', err);
            });
        }

        function refreshSystemInfo() {
            fetch('/api/system-info')
            .then(r => r.json())
            .then(data => {
                const infoDiv = document.getElementById('system-info');
                infoDiv.innerHTML = `
                    <p><strong>Railway Port:</strong> ${data.port}</p>
                    <p><strong>Environment:</strong> ${data.environment}</p>
                    <p><strong>Admin Authenticated:</strong> ${data.admin_authenticated ? '✅' : '❌'}</p>
                    <p><strong>Google APIs:</strong> ${data.google_apis_available ? '✅' : '❌'}</p>
                    <p><strong>Google Credentials:</strong> ${data.google_credentials_available ? '✅' : '❌'}</p>
                    <p><strong>Gmail Connected:</strong> ${data.gmail_authenticated ? '✅' : '❌'}</p>
                    <p><strong>Deployment Status:</strong> ${data.deployment_status}</p>
                `;
            })
            .catch(err => {
                console.error('System info error:', err);
                document.getElementById('system-info').innerHTML = '<p style="color: red;">Failed to load system information</p>';
            });
        }

        function refreshLogs() {
            fetch('/api/logs')
            .then(r => r.json())
            .then(data => {
                if (data.logs && data.logs.length > 0) {
                    document.getElementById('logs').innerHTML = data.logs.slice(-10).join('<br>');
                }
            })
            .catch(err => {
                console.error('Logs error:', err);
            });
        }

        // Handle Enter key in password field
        document.getElementById('admin-password').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                authenticate();
            }
        });
        </script>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/api/auth', methods=['POST'])
def api_auth():
    """Railway admin authentication - UNCHANGED"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            return jsonify({'success': False, 'message': 'Invalid password'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Authentication error: {str(e)}'})

@app.route('/api/system-info')
def api_system_info():
    """Railway system information - ENHANCED"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        return jsonify({
            'port': os.environ.get('PORT', 'Not Set'),
            'environment': 'Railway',
            'admin_authenticated': session.get('admin_authenticated', False),
            'google_apis_available': GOOGLE_APIS_AVAILABLE,
            'google_credentials_available': bool(os.environ.get('GOOGLE_CLIENT_ID')),
            'gmail_authenticated': scanner.gmail_service is not None,
            'deployment_status': 'Active',
            'timestamp': datetime.now().isoformat(),
            'railway_deployment': True
        })
    except Exception as e:
        return jsonify({'error': f'System info failed: {str(e)}'}), 500

# NEW Gmail API endpoints
@app.route('/api/gmail/start-oauth', methods=['POST'])
def api_gmail_start_oauth():
    """Start Gmail OAuth"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        result = scanner.start_oauth()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/complete-oauth', methods=['POST'])
def api_gmail_complete_oauth():
    """Complete Gmail OAuth"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        data = request.get_json()
        auth_code = data.get('auth_code', '')
        result = scanner.complete_oauth(auth_code)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/basic-scan', methods=['POST'])
def api_gmail_basic_scan():
    """Basic Gmail scan"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        result = scanner.basic_gmail_scan(100)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/logs')
def api_logs():
    """Get activity logs"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        return jsonify({'logs': scanner.logs[-20:]})  # Last 20 logs
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/health')
def health_check():
    """Railway health check endpoint - UNCHANGED"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'VLSI Resume Scanner is running successfully on Railway',
        'railway_deployment': True,
        'gmail_functionality': GOOGLE_APIS_AVAILABLE
    })

@app.route('/api/test')
def api_test():
    """Simple API test endpoint for Railway - UNCHANGED"""
    return jsonify({
        'message': 'Railway deployment API test successful!',
        'timestamp': datetime.now().isoformat(),
        'status': 'success',
        'railway_environment': True,
        'gmail_apis': GOOGLE_APIS_AVAILABLE
    })

# Error handlers - UNCHANGED
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found', 
        'available_endpoints': ['/', '/health', '/api/test', '/api/auth', '/api/system-info'],
        'railway_deployment': True
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'railway_deployment': True
    }), 500

# RAILWAY DEPLOYMENT ENTRY POINT - UNCHANGED
if __name__ == '__main__':
    # Railway deployment configuration
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    print(f"🚀 Starting VLSI Resume Scanner on Railway")
    print(f"📊 Port: {port}")
    print(f"🔧 Debug Mode: {debug_mode}")
    print(f"📧 Google APIs Available: {GOOGLE_APIS_AVAILABLE}")
    
    app.run(
        debug=debug_mode, 
        host='0.0.0.0', 
        port=port
    )
