import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-2024')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# Check if Google APIs are available
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_APIS_AVAILABLE = True
except ImportError:
    GOOGLE_APIS_AVAILABLE = False

# MINIMAL Gmail scanner class - back to working version
class BasicGmailScanner:
    def __init__(self):
        self.gmail_service = None
        self.credentials = None
        self.logs = []
        self.client_config = None
        
    def add_log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_entry)
        print(log_entry)
    
    def setup_oauth_credentials(self, client_id, client_secret):
        """Setup OAuth credentials from GUI input"""
        try:
            if not client_id or not client_secret:
                return {'success': False, 'error': 'Both Client ID and Client Secret are required'}
            
            client_id = client_id.strip()
            client_secret = client_secret.strip()
            
            if len(client_id) < 50:
                return {'success': False, 'error': 'Client ID appears invalid (too short - should be ~70 characters)'}
            
            if len(client_secret) < 20:
                return {'success': False, 'error': 'Client Secret appears invalid (too short - should be ~24 characters)'}
            
            # Create client configuration
            self.client_config = {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"]
                // Handle Enter key
            }
            
            # Store in session for persistence
            session['oauth_client_config'] = self.client_config
            
            self.add_log("OAuth credentials configured successfully via GUI")
            return {'success': True, 'message': 'OAuth credentials configured successfully'}
            
        except Exception as e:
            self.add_log(f"OAuth credential setup failed: {e}", "ERROR")
    def start_simple_oauth(self):
        """Start simple OAuth flow - manual URL generation"""
        try:
            if not self.client_config:
                self.client_config = session.get('oauth_client_config')
                
            if not self.client_config:
                return {'success': False, 'error': 'OAuth credentials not configured'}
            
            self.add_log("Starting simple Gmail OAuth flow")
            
            # Manual OAuth URL generation (no imports that might cause issues)
            client_id = self.client_config['installed']['client_id']
            
            # Build URL manually without urllib import
            base_url = 'https://accounts.google.com/o/oauth2/auth'
            params = [
                f'client_id={client_id}',
                'redirect_uri=urn:ietf:wg:oauth:2.0:oob',
                'scope=https://www.googleapis.com/auth/gmail.readonly',
                'response_type=code',
                'access_type=offline'
            ]
            
            auth_url = base_url + '?' + '&'.join(params)
            
            self.add_log("OAuth URL generated successfully")
            
            return {
                'success': True, 
                'auth_url': auth_url,
                'instructions': [
                    "1. Click the link below to open Google authorization",
                    "2. Sign in and grant Gmail permissions",
                    "3. Copy the authorization code Google provides",
                    "4. Paste it back here and click Complete"
                ]
            }
            
        except Exception as e:
            self.add_log(f"Simple OAuth start failed: {e}", "ERROR")
            return {'success': False, 'error': str(e)}
    
    def get_credentials_status(self):
        """Check if OAuth credentials are configured"""
        if self.client_config:
            return {
                'configured': True,
                'client_id_preview': self.client_config['installed']['client_id'][:20] + '...',
                'has_secret': bool(self.client_config['installed']['client_secret'])
            }
        
        # Try session
        session_config = session.get('oauth_client_config')
        if session_config:
            self.client_config = session_config
            return {
                'configured': True,
                'client_id_preview': session_config['installed']['client_id'][:20] + '...',
                'has_secret': bool(session_config['installed']['client_secret'])
            }
        
        return {'configured': False}
    
    def clear_credentials(self):
        """Clear stored OAuth credentials"""
        try:
            self.client_config = None
            session.pop('oauth_client_config', None)
            session.pop('gmail_credentials', None)
            self.gmail_service = None
            self.credentials = None
            self.add_log("OAuth credentials cleared from GUI")
            return {'success': True, 'message': 'Credentials cleared successfully'}
        except Exception as e:
            self.add_log(f"Clear credentials failed: {e}", "ERROR")
            return {'success': False, 'error': str(e)}
    
    def test_oauth_setup(self):
        """Test if OAuth is ready - simple check without complex operations"""
        try:
            if not GOOGLE_APIS_AVAILABLE:
                return {'success': False, 'error': 'Google APIs not available'}
            
            if not self.client_config:
                self.client_config = session.get('oauth_client_config')
                
            if not self.client_config:
                return {'success': False, 'error': 'OAuth credentials not configured'}
            
            self.add_log("OAuth setup test successful")
            return {'success': True, 'message': 'OAuth setup is ready for testing'}
            
        except Exception as e:
            self.add_log(f"OAuth test failed: {e}", "ERROR")
            return {'success': False, 'error': str(e)}

# Initialize scanner
scanner = BasicGmailScanner()

@app.route('/')
def index():
    """Working Railway deployment page with safe credential setup"""
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
            .btn:disabled { background: #ccc; cursor: not-allowed; }
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
            .instructions {
                background: #f8f9fa; padding: 15px; border-radius: 5px;
                margin: 10px 0; text-align: left; font-size: 0.9em;
            }
            .instructions ol {
                margin-left: 20px;
            }
            .credentials-configured {
                background: #d4edda; border: 1px solid #c3e6cb;
                color: #155724; padding: 15px; border-radius: 5px;
            }
            .credentials-missing {
                background: #f8d7da; border: 1px solid #f5c6cb;
                color: #721c24; padding: 15px; border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔬 VLSI Resume Scanner</h1>
                <p>Railway Deployment - Safe Step-by-Step Setup</p>
            </div>
            
            <div class="content">
                <div class="status">
                    <h3>✅ Railway Deployment Active!</h3>
                    <p>Application ready - adding features step by step safely</p>
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
                    <h2>🎛️ Gmail Scanner Setup</h2>
                    <p>Welcome! Let's set up Gmail access step by step.</p>
                    
                    <div class="auth-section">
                        <h4>🔑 Step 1: Configure Google OAuth Credentials</h4>
                        <div id="credentials-status">Loading credentials status...</div>
                        
                        <div id="credentials-form" style="margin-top: 15px;">
                            <p>Enter your Google Cloud Console OAuth credentials:</p>
                            <div class="input-group">
                                <input type="text" id="client-id" placeholder="Google Client ID" style="min-width: 400px;">
                            </div>
                            <div class="input-group">
                                <input type="password" id="client-secret" placeholder="Google Client Secret" style="min-width: 300px;">
                            </div>
                            <button onclick="setupCredentials()" class="btn btn-success">💾 Save Credentials</button>
                            <button onclick="clearCredentials()" class="btn" style="background: #6c757d;">🗑️ Clear</button>
                        </div>
                        
                        <div class="instructions" style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin-top: 15px; text-align: left;">
                            <h6>📋 How to get Google OAuth credentials:</h6>
                            <ol style="margin-left: 20px;">
                                <li>Go to <a href="https://console.cloud.google.com" target="_blank" style="color: #4a90e2;">Google Cloud Console</a></li>
                                <li>Create a new project or select existing one</li>
                                <li>Enable Gmail API in "APIs & Services" → "Library"</li>
                                <li>Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"</li>
                                <li>Choose "Desktop Application" as application type</li>
                                <li>Copy the Client ID and Client Secret here</li>
                            </ol>
                        </div>
                    </div>

                    <div class="auth-section">
                        <h4>📧 Step 2: Test OAuth Setup</h4>
                        <p>Once credentials are configured, test the OAuth setup before proceeding.</p>
                        <button onclick="testOAuthSetup()" class="btn" disabled id="test-oauth-btn">🧪 Test OAuth Setup</button>
                        <div id="oauth-test-results" style="margin-top: 10px;"></div>
                    </div>

                    <div class="auth-section">
                        <h4>📧 Step 3: Manual OAuth Setup</h4>
                        <p>Your credentials are ready! Use them to manually set up OAuth:</p>
                        
                        <div class="instructions">
                            <h6>📋 Manual OAuth Instructions:</h6>
                            <ol style="margin-left: 20px;">
                                <li>Go to: <code>https://accounts.google.com/o/oauth2/auth</code></li>
                                <li>Add these parameters:</li>
                                <ul style="margin-left: 20px; font-family: monospace; font-size: 0.9em;">
                                    <li><strong>client_id:</strong> [Your Client ID from Step 1]</li>
                                    <li><strong>redirect_uri:</strong> urn:ietf:wg:oauth:2.0:oob</li>
                                    <li><strong>scope:</strong> https://www.googleapis.com/auth/gmail.readonly</li>
                                    <li><strong>response_type:</strong> code</li>
                                    <li><strong>access_type:</strong> offline</li>
                                </ul>
                                <li>Complete authorization and get code</li>
                                <li>OAuth token exchange will be implemented next</li>
                            </ol>
                        </div>
                        
                        <button onclick="showOAuthURL()" class="btn">📋 Generate OAuth URL</button>
                        <div id="manual-oauth-url" style="margin-top: 10px;"></div>
                    </div>

                    <div class="auth-section">
                        <h4>📊 Step 4: Next Features</h4>
                        <p>✅ Credential setup working<br>
                           ⏳ OAuth flow (implementing safely)<br>
                           🔜 Email scanning<br>
                           🔜 Resume processing</p>
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
                        checkCredentialsStatus();
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

            function checkCredentialsStatus() {
                log("🔄 Checking credentials status...");
                
                fetch('/api/gmail/credentials-status')
                .then(r => r.json())
                .then(data => {
                    const statusDiv = document.getElementById('credentials-status');
                    const testBtn = document.getElementById('test-oauth-btn');
                    const credentialsForm = document.getElementById('credentials-form');
                    
                    if (data.configured) {
                        statusDiv.innerHTML = `
                            <div class="credentials-configured">
                                <h5>✅ OAuth Credentials Configured</h5>
                                <p><strong>Client ID:</strong> ${data.client_id_preview}</p>
                                <p><strong>Client Secret:</strong> ${data.has_secret ? '✅ Set' : '❌ Missing'}</p>
                            </div>
                        `;
                        testBtn.disabled = false;
                        testBtn.textContent = '🧪 Test OAuth Setup';
                        credentialsForm.style.display = 'none';
                        log("✅ Credentials are configured");
                    } else {
                        statusDiv.innerHTML = `
                            <div class="credentials-missing">
                                <h5>❌ OAuth Credentials Not Configured</h5>
                                <p>Please enter your Google Cloud Console credentials below.</p>
                            </div>
                        `;
                        testBtn.disabled = true;
                        testBtn.textContent = '⚠️ Configure credentials first';
                        credentialsForm.style.display = 'block';
                        log("❌ Credentials not configured");
                    }
                })
                .catch(err => {
                    log(`❌ Failed to check credentials: ${err.message}`);
                });
            }

            function setupCredentials() {
                log("🔄 Setting up credentials...");
                
                const clientId = document.getElementById('client-id').value.trim();
                const clientSecret = document.getElementById('client-secret').value.trim();
                
                log(`📝 Client ID length: ${clientId.length}`);
                log(`📝 Client Secret length: ${clientSecret.length}`);
                
                if (!clientId || !clientSecret) {
                    alert('Please enter both Client ID and Client Secret');
                    log("❌ Missing credentials");
                    return;
                }
                
                log("📡 Sending credentials to server...");
                
                fetch('/api/gmail/setup-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        client_id: clientId,
                        client_secret: clientSecret 
                    })
                })
                .then(r => r.json())
                .then(data => {
                    log(`📥 Setup response: ${JSON.stringify(data)}`);
                    
                    if (data.success) {
                        alert('✅ OAuth credentials configured successfully!');
                        document.getElementById('client-id').value = '';
                        document.getElementById('client-secret').value = '';
                        checkCredentialsStatus();
                        refreshLogs();
                        log("✅ Credentials setup successful");
                    } else {
                        alert('❌ Failed to configure credentials: ' + data.error);
                        log(`❌ Setup failed: ${data.error}`);
                    }
                })
                .catch(err => {
                    log(`❌ Setup request failed: ${err.message}`);
                    alert('Failed to save credentials: ' + err.message);
                });
            }

            function clearCredentials() {
                if (!confirm('Are you sure you want to clear the stored OAuth credentials?')) {
                    return;
                }
                
                log("🔄 Clearing credentials...");
                
                fetch('/api/gmail/clear-credentials', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('✅ Credentials cleared successfully');
                        document.getElementById('client-id').value = '';
                        document.getElementById('client-secret').value = '';
                        checkCredentialsStatus();
                        refreshLogs();
                        log("✅ Credentials cleared");
                    } else {
                        alert('❌ Failed to clear credentials: ' + data.error);
                        log(`❌ Clear failed: ${data.error}`);
                    }
                })
                .catch(err => {
                    log(`❌ Clear request failed: ${err.message}`);
                    alert('Failed to clear credentials: ' + err.message);
                });
            }

            function testOAuthSetup() {
                log("🔄 Testing OAuth setup...");
                
                document.getElementById('test-oauth-btn').disabled = true;
                document.getElementById('test-oauth-btn').textContent = '⏳ Testing...';
                
                fetch('/api/gmail/test-oauth', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    const resultsDiv = document.getElementById('oauth-test-results');
                    
                    if (data.success) {
                        resultsDiv.innerHTML = `
                            <div class="credentials-configured">
                                <h6>✅ OAuth Setup Test Successful</h6>
                                <p>${data.message}</p>
                            </div>
                        `;
                        log("✅ OAuth test successful");
                    } else {
                        resultsDiv.innerHTML = `
                            <div class="credentials-missing">
                                <h6>❌ OAuth Setup Test Failed</h6>
                                <p>${data.error}</p>
                            </div>
                        `;
                        log(`❌ OAuth test failed: ${data.error}`);
                    }
                    
                    document.getElementById('test-oauth-btn').disabled = false;
                    document.getElementById('test-oauth-btn').textContent = '🧪 Test OAuth Setup';
                    refreshLogs();
                })
                .catch(err => {
                    log(`❌ OAuth test request failed: ${err.message}`);
                    document.getElementById('oauth-test-results').innerHTML = `
                        <div class="credentials-missing">
                            <h6>❌ Test Request Failed</h6>
                            <p>${err.message}</p>
                        </div>
                    `;
                    document.getElementById('test-oauth-btn').disabled = false;
                    document.getElementById('test-oauth-btn').textContent = '🧪 Test OAuth Setup';
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
                        <p><strong>OAuth Credentials:</strong> ${data.oauth_credentials_configured ? '✅' : '❌'}</p>
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

            function showOAuthURL() {
                log("🔄 Generating OAuth URL manually...");
                
                fetch('/api/gmail/credentials-status')
                .then(r => r.json())
                .then(data => {
                    if (data.configured) {
                        // Since we can't safely get the actual client_id without causing crashes,
                        // show the manual instructions
                        document.getElementById('manual-oauth-url').innerHTML = `
                            <div class="credentials-configured">
                                <h6>📋 Manual OAuth URL Construction:</h6>
                                <p><strong>Base URL:</strong> https://accounts.google.com/o/oauth2/auth</p>
                                <p><strong>Parameters to add:</strong></p>
                                <ul style="text-align: left; margin-left: 20px; font-family: monospace; font-size: 0.9em;">
                                    <li>client_id=[Your Client ID from Step 1]</li>
                                    <li>redirect_uri=urn:ietf:wg:oauth:2.0:oob</li>
                                    <li>scope=https://www.googleapis.com/auth/gmail.readonly</li>
                                    <li>response_type=code</li>
                                    <li>access_type=offline</li>
                                </ul>
                                <p><small>⚠️ Automatic URL generation temporarily disabled to prevent worker crashes</small></p>
                            </div>
                        `;
                        log("✅ Manual OAuth instructions shown");
                    } else {
                        alert('Please configure credentials first');
                    }
                })
                .catch(err => {
                    log(`❌ Failed to show OAuth URL: ${err.message}`);
                });
            }
            document.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && document.getElementById('auth-section').style.display !== 'none') {
                    login();
                }
            });

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                log("🚀 Page loaded successfully");
                log("🔧 Admin password: admin123");
                log("📋 Safe step-by-step setup ready");
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

@app.route('/api/gmail/setup-credentials', methods=['POST'])
def api_gmail_setup_credentials():
    """Setup OAuth credentials via GUI"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        client_id = data.get('client_id', '')
        client_secret = data.get('client_secret', '')
        
        print(f"Setting up credentials - Client ID length: {len(client_id)}, Secret length: {len(client_secret)}")
        
        result = scanner.setup_oauth_credentials(client_id, client_secret)
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Credentials setup failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/credentials-status')
def api_gmail_credentials_status():
    """Get OAuth credentials configuration status"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        status = scanner.get_credentials_status()
        return jsonify(status)
    except Exception as e:
        scanner.add_log(f"Credentials status check failed: {e}", "ERROR")
        return jsonify({'configured': False, 'error': str(e)})

@app.route('/api/gmail/clear-credentials', methods=['POST'])
def api_gmail_clear_credentials():
    """Clear stored OAuth credentials"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        result = scanner.clear_credentials()
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Clear credentials failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/start-simple-oauth', methods=['POST'])
def api_gmail_start_simple_oauth():
    """Start simple Gmail OAuth flow"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        result = scanner.start_simple_oauth()
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Simple OAuth start failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/complete-simple-oauth', methods=['POST'])
def api_gmail_complete_simple_oauth():
    """Complete simple Gmail OAuth flow - placeholder for now"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        auth_code = data.get('auth_code', '')
        
        scanner.add_log(f"Received OAuth completion request with code: {auth_code[:10]}...")
        
        # For now, just simulate success to test the flow
        return jsonify({
            'success': True,
            'email': 'test@example.com',
            'total_messages': 1234,
            'message': 'OAuth completion simulation - real implementation coming next'
        })
        
    except Exception as e:
        scanner.add_log(f"Simple OAuth completion failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/test-oauth', methods=['POST'])
def api_gmail_test_oauth():
    """Test OAuth setup without complex operations"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        result = scanner.test_oauth_setup()
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"OAuth test failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

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
            'oauth_credentials_configured': scanner.get_credentials_status()['configured'],
            'deployment_status': 'Active - Safe Step-by-Step',
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
        'message': 'VLSI Resume Scanner - Safe Step-by-Step',
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
    
    print(f"🚀 Starting VLSI Resume Scanner - Safe Version")
    print(f"📊 Port: {port}")
    print(f"🔑 Admin password: '{ADMIN_PASSWORD}'")
    print(f"📧 Google APIs Available: {GOOGLE_APIS_AVAILABLE}")
    
    scanner.add_log("Application starting up - safe step-by-step mode")
    
    app.run(
        debug=debug_mode, 
        host='0.0.0.0', 
        port=port
    )
