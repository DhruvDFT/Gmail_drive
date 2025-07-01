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
    def start_oauth_flow(self):
        """Start Gmail OAuth flow using stored credentials"""
        try:
            if not GOOGLE_APIS_AVAILABLE:
                return {'success': False, 'error': 'Google APIs not installed'}
            
            if not self.client_config:
                # Try to restore from session
                self.client_config = session.get('oauth_client_config')
                
            if not self.client_config:
                return {'success': False, 'error': 'OAuth credentials not configured. Please setup credentials first.'}
            
            self.add_log("Starting Gmail OAuth flow")
            
            # Simple manual OAuth URL generation (more reliable)
            client_id = self.client_config['installed']['client_id']
            
            import urllib.parse
            params = {
                'client_id': client_id,
                'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
                'scope': 'https://www.googleapis.com/auth/gmail.readonly',
                'response_type': 'code',
                'access_type': 'offline',
                'prompt': 'consent'
            }
            
            auth_url = 'https://accounts.google.com/o/oauth2/auth?' + urllib.parse.urlencode(params)
            
            self.add_log(f"OAuth URL generated successfully")
            
            return {
                'success': True, 
                'auth_url': auth_url,
                'instructions': [
                    "1. Click the authorization URL below",
                    "2. Sign in to your Google account", 
                    "3. Grant Gmail permissions to this application",
                    "4. Copy the authorization code from Google",
                    "5. Paste the code back here and click Complete"
                ]
            }
            
        except Exception as e:
            self.add_log(f"OAuth flow start failed: {e}", "ERROR")
            return {'success': False, 'error': f'OAuth flow failed: {str(e)}'}
    
    def complete_oauth_flow(self, auth_code):
        """Complete Gmail OAuth flow with authorization code"""
        try:
            if not auth_code or len(auth_code.strip()) < 10:
                return {'success': False, 'error': 'Invalid authorization code provided'}
            
            auth_code = auth_code.strip()
            self.add_log(f"Completing OAuth with code: {auth_code[:10]}...")
            
            if not self.client_config:
                self.client_config = session.get('oauth_client_config')
                
            if not self.client_config:
                return {'success': False, 'error': 'OAuth session expired. Please restart the flow.'}
            
            # Manual token exchange (more reliable than InstalledAppFlow)
            import urllib.parse, urllib.request, json
            
            client_id = self.client_config['installed']['client_id']
            client_secret = self.client_config['installed']['client_secret']
            
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
            
            if 'error' in token_response:
                return {'success': False, 'error': f"Token exchange failed: {token_response.get('error_description', 'Unknown error')}"}
            
            # Create credentials manually
            self.credentials = Credentials(
                token=token_response.get('access_token'),
                refresh_token=token_response.get('refresh_token'),
                token_uri='https://oauth2.googleapis.com/token',
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Create Gmail service
            self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
            
            # Test connection and get user info
            profile = self.gmail_service.users().getProfile(userId='me').execute()
            email_address = profile.get('emailAddress', 'Unknown')
            total_messages = profile.get('messagesTotal', 0)
            
            # Store credentials in session for persistence
            session['gmail_credentials'] = {
                'token': self.credentials.token,
                'refresh_token': self.credentials.refresh_token,
                'token_uri': self.credentials.token_uri,
                'client_id': self.credentials.client_id,
                'client_secret': self.credentials.client_secret
            }
            
            self.add_log(f"Gmail authentication successful for: {email_address}")
            
            return {
                'success': True,
                'email': email_address,
                'total_messages': total_messages
            }
            
        except Exception as e:
            self.add_log(f"OAuth completion failed: {e}", "ERROR")
            return {'success': False, 'error': f'OAuth completion failed: {str(e)}'}
    
    def get_gmail_status(self):
        """Get current Gmail connection status"""
        try:
            if not self.gmail_service:
                # Try to restore from session
                creds_data = session.get('gmail_credentials')
                if creds_data:
                    try:
                        self.credentials = Credentials(
                            token=creds_data['token'],
                            refresh_token=creds_data.get('refresh_token'),
                            token_uri=creds_data['token_uri'],
                            client_id=creds_data['client_id'],
                            client_secret=creds_data['client_secret']
                        )
                        self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
                    except Exception as e:
                        self.add_log(f"Failed to restore Gmail credentials: {e}", "ERROR")
                        return {
                            'connected': False,
                            'email': None,
                            'status': 'Credentials restoration failed'
                        }
            
            if not self.gmail_service:
                return {
                    'connected': False,
                    'email': None,
                    'status': 'Not connected'
                }
            
            # Test current connection
            profile = self.gmail_service.users().getProfile(userId='me').execute()
            email = profile.get('emailAddress', 'Unknown')
            
            return {
                'connected': True,
                'email': email,
                'status': 'Active connection',
                'total_messages': profile.get('messagesTotal', 0)
            }
            
        except Exception as e:
            self.add_log(f"Gmail status check failed: {e}", "ERROR")
            # Clear invalid credentials
            self.gmail_service = None
            self.credentials = None
            return {
                'connected': False,
                'email': None,
                'status': f'Connection error: {str(e)}'
            }
    
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
            self.add_log("OAuth credentials cleared from GUI")
            return {'success': True, 'message': 'Credentials cleared successfully'}
        except Exception as e:
            self.add_log(f"Clear credentials failed: {e}", "ERROR")
            return {'success': False, 'error': str(e)}

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
            function checkGmailStatus() {
                log("🔄 Checking Gmail connection status...");
                
                fetch('/api/gmail/status')
                .then(r => r.json())
                .then(data => {
                    const statusDiv = document.getElementById('gmail-status');
                    const scanBtn = document.getElementById('scan-btn');
                    
                    if (data.connected) {
                        statusDiv.innerHTML = `
                            <div class="credentials-configured">
                                <h5>✅ Gmail Connected</h5>
                                <p><strong>Email:</strong> ${data.email}</p>
                                <p><strong>Total Messages:</strong> ${data.total_messages || 'Unknown'}</p>
                                <p><strong>Status:</strong> ${data.status}</p>
                            </div>
                        `;
                        document.getElementById('oauth-flow-section').style.display = 'none';
                        scanBtn.disabled = false;
                        scanBtn.textContent = '📊 Start Email Scan';
                        log("✅ Gmail is connected");
                    } else {
                        statusDiv.innerHTML = `
                            <div class="credentials-missing">
                                <h5>❌ Gmail Not Connected</h5>
                                <p><strong>Status:</strong> ${data.status}</p>
                                <p>Click "Start Gmail OAuth" below to authenticate.</p>
                            </div>
                        `;
                        document.getElementById('oauth-flow-section').style.display = 'block';
                        scanBtn.disabled = true;
                        scanBtn.textContent = '⚠️ Connect Gmail first';
                        log("❌ Gmail not connected");
                    }
                })
                .catch(err => {
                    log(`❌ Failed to check Gmail status: ${err.message}`);
                    document.getElementById('gmail-status').innerHTML = 
                        '<div class="credentials-missing">❌ Failed to check Gmail status</div>';
                });
            }

            function startGmailOAuth() {
                log("🔄 Starting Gmail OAuth flow...");
                
                document.getElementById('start-oauth-btn').textContent = '⏳ Starting OAuth...';
                document.getElementById('start-oauth-btn').disabled = true;
                
                fetch('/api/gmail/start-oauth', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    log(`📥 OAuth start response: ${JSON.stringify(data)}`);
                    
                    if (data.success) {
                        document.getElementById('oauth-instructions').classList.remove('hidden');
                        
                        // Show instructions
                        const instructionList = document.getElementById('instruction-list');
                        instructionList.innerHTML = '<ol style="margin-left: 20px;">' + 
                            data.instructions.map(inst => `<li>${inst}</li>`).join('') + 
                            '</ol>';
                        
                        // Show auth URL
                        document.getElementById('auth-url').innerHTML = 
                            `<a href="${data.auth_url}" target="_blank" style="color: #4a90e2; text-decoration: none;">${data.auth_url}</a>`;
                        
                        document.getElementById('start-oauth-btn').textContent = '⏳ Waiting for authorization...';
                        log("✅ OAuth flow started successfully");
                    } else {
                        alert('❌ Failed to start OAuth: ' + data.error);
                        document.getElementById('start-oauth-btn').textContent = '🚀 Start Gmail OAuth';
                        document.getElementById('start-oauth-btn').disabled = false;
                        log(`❌ OAuth start failed: ${data.error}`);
                    }
                })
                .catch(err => {
                    log(`❌ OAuth start request failed: ${err.message}`);
                    alert('OAuth request failed: ' + err.message);
                    document.getElementById('start-oauth-btn').textContent = '🚀 Start Gmail OAuth';
                    document.getElementById('start-oauth-btn').disabled = false;
                });
            }

            function completeGmailOAuth() {
                const authCode = document.getElementById('auth-code').value.trim();
                if (!authCode) {
                    alert('Please enter the authorization code from Google');
                    return;
                }
                
                log(`🔄 Completing OAuth with code: ${authCode.substring(0, 10)}...`);
                
                fetch('/api/gmail/complete-oauth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ auth_code: authCode })
                })
                .then(r => r.json())
                .then(data => {
                    log(`📥 OAuth complete response: ${JSON.stringify(data)}`);
                    
                    if (data.success) {
                        alert(`✅ Gmail authentication successful!\\nEmail: ${data.email}\\nTotal Messages: ${data.total_messages}`);
                        document.getElementById('oauth-instructions').classList.add('hidden');
                        document.getElementById('auth-code').value = '';
                        checkGmailStatus();
                        refreshLogs();
                        log("✅ Gmail OAuth completed successfully");
                    } else {
                        alert('❌ OAuth completion failed: ' + data.error);
                        log(`❌ OAuth completion failed: ${data.error}`);
                    }
                })
                .catch(err => {
                    log(`❌ OAuth completion request failed: ${err.message}`);
                    alert('OAuth completion failed: ' + err.message);
                });
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
                        <h4>🔑 Step 1: Configure Google OAuth Credentials</h4>
                        <div id="credentials-status">Loading credentials status...</div>
                        
                        <div id="credentials-form" style="margin-top: 15px;">
                            <p>Enter your Google Cloud Console OAuth credentials:</p>
                            <div class="input-group">
                                <input type="text" id="client-id" placeholder="Google Client ID (starts with numbers)" style="min-width: 400px;">
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
                        <h4>📧 Step 2: Gmail OAuth Authentication</h4>
                        <div id="gmail-status">Loading Gmail status...</div>
                        
                        <div id="oauth-flow-section" style="margin-top: 15px;">
                            <button onclick="startGmailOAuth()" class="btn btn-success" id="start-oauth-btn" disabled>🚀 Start Gmail OAuth</button>
                            
                            <div id="oauth-instructions" class="hidden" style="margin-top: 15px;">
                                <div class="instructions">
                                    <h6>📋 OAuth Authorization Steps:</h6>
                                    <div id="instruction-list"></div>
                                    <p><strong>Authorization URL:</strong></p>
                                    <div id="auth-url" style="background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all; margin: 10px 0; font-size: 0.9em; max-height: 100px; overflow-y: auto;"></div>
                                    <div class="input-group">
                                        <input type="text" id="auth-code" placeholder="Paste authorization code here" style="min-width: 300px; font-family: monospace;">
                                        <button onclick="completeGmailOAuth()" class="btn">✅ Complete OAuth</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="auth-section">
                        <h4>📊 Step 3: Email Scanning</h4>
                        <p>Complete Gmail authentication above to enable email scanning features.</p>
                        <button class="btn" disabled id="scan-btn">📊 Start Email Scan</button>
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
                        checkGmailStatus();
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

            function checkCredentialsStatus() {
                log("🔄 Checking credentials status...");
                
                fetch('/api/gmail/credentials-status')
                .then(r => r.json())
                .then(data => {
                    const statusDiv = document.getElementById('credentials-status');
                    const gmailBtn = document.getElementById('gmail-setup-btn');
                    const credentialsForm = document.getElementById('credentials-form');
                    const startOAuthBtn = document.getElementById('start-oauth-btn');
                    
                    if (data.configured) {
                        statusDiv.innerHTML = `
                            <div class="credentials-configured">
                                <h5>✅ OAuth Credentials Configured</h5>
                                <p><strong>Client ID:</strong> ${data.client_id_preview}</p>
                                <p><strong>Client Secret:</strong> ${data.has_secret ? '✅ Set' : '❌ Missing'}</p>
                            </div>
                        `;
                        gmailBtn.disabled = false;
                        gmailBtn.textContent = '🚀 Ready for Gmail OAuth';
                        startOAuthBtn.disabled = false;
                        startOAuthBtn.textContent = '🚀 Start Gmail OAuth';
                        credentialsForm.style.display = 'none';
                        log("✅ Credentials are configured");
                    } else {
                        statusDiv.innerHTML = `
                            <div class="credentials-missing">
                                <h5>❌ OAuth Credentials Not Configured</h5>
                                <p>Please enter your Google Cloud Console credentials below.</p>
                            </div>
                        `;
                        gmailBtn.disabled = true;
                        gmailBtn.textContent = '⚠️ Configure credentials first';
                        startOAuthBtn.disabled = true;
                        startOAuthBtn.textContent = '⚠️ Configure credentials first';
                        credentialsForm.style.display = 'block';
                        log("❌ Credentials not configured");
                    }
                })
                .catch(err => {
                    log(`❌ Failed to check credentials: ${err.message}`);
                    document.getElementById('credentials-status').innerHTML = 
                        '<div class="credentials-missing">❌ Failed to check credentials status</div>';
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
            document.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && document.getElementById('auth-section').style.display !== 'none') {
                    login();
                }
            });

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                log("🚀 Page loaded successfully");
                log("🔧 Admin password: admin123");
                log("📋 Ready for OAuth credential setup");
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

@app.route('/api/gmail/start-oauth', methods=['POST'])
def api_gmail_start_oauth():
    """Start Gmail OAuth flow"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        result = scanner.start_oauth_flow()
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Gmail OAuth start failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/complete-oauth', methods=['POST'])
def api_gmail_complete_oauth():
    """Complete Gmail OAuth flow"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        auth_code = data.get('auth_code', '')
        result = scanner.complete_oauth_flow(auth_code)
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Gmail OAuth completion failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/status')
def api_gmail_status():
    """Get Gmail connection status"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        status = scanner.get_gmail_status()
        return jsonify(status)
    except Exception as e:
        scanner.add_log(f"Gmail status check failed: {e}", "ERROR")
        return jsonify({'connected': False, 'status': f'Error: {str(e)}'})

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
            'deployment_status': 'Active with GUI OAuth',
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
