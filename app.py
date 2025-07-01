import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session

# OPTIONAL: Try to import Google APIs (won't break if missing)
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    import pickle
    GOOGLE_APIS_AVAILABLE = True
except ImportError:
    GOOGLE_APIS_AVAILABLE = False

app = Flask(__name__)

# RAILWAY DEPLOYMENT LOGIC - CORE ESSENTIALS (UNCHANGED)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-2024')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# ENHANCED Gmail scanner class with proper OAuth
class EnhancedGmailScanner:
    def __init__(self):
        self.gmail_service = None
        self.credentials = None
        self.logs = []
        
        # OAuth configuration
        self.SCOPES = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.metadata'
        ]
        
        # GUI-based OAuth settings (no environment variables needed)
        self.client_config = None  # Will be set via GUI
        
    def add_log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_entry)
        print(log_entry)  # Railway logs
        
    def setup_oauth_credentials(self, client_id, client_secret):
        """Setup OAuth credentials from GUI input"""
        try:
            if not client_id or not client_secret:
                return {'success': False, 'error': 'Both Client ID and Client Secret are required'}
            
            if len(client_id.strip()) < 50:
                return {'success': False, 'error': 'Client ID appears invalid (too short)'}
            
            if len(client_secret.strip()) < 20:
                return {'success': False, 'error': 'Client Secret appears invalid (too short)'}
            
            # Create client configuration
            self.client_config = {
                "installed": {
                    "client_id": client_id.strip(),
                    "client_secret": client_secret.strip(),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"]
                }
            }
            
            # Store in session for persistence
            session['oauth_client_config'] = self.client_config
            
            self.add_log("OAuth credentials configured successfully via GUI")
            return {'success': True, 'message': 'OAuth credentials configured successfully'}
            
        except Exception as e:
            self.add_log(f"OAuth credential setup failed: {e}", "ERROR")
            return {'success': False, 'error': str(e)}
    
    def validate_environment(self):
        """Validate OAuth setup - now checks GUI credentials"""
        try:
            if not GOOGLE_APIS_AVAILABLE:
                return {'success': False, 'error': 'Google APIs not installed. Run: pip install google-auth google-auth-oauthlib google-api-python-client'}
            
            if not self.client_config:
                # Try to restore from session
                self.client_config = session.get('oauth_client_config')
                
            if not self.client_config:
                return {'success': False, 'error': 'OAuth credentials not configured. Please enter your Google Client ID and Secret.'}
            
            client_id = self.client_config.get('installed', {}).get('client_id', '')
            client_secret = self.client_config.get('installed', {}).get('client_secret', '')
            
            if not client_id or not client_secret:
                return {'success': False, 'error': 'Invalid OAuth configuration. Please re-enter credentials.'}
                
            self.add_log("OAuth environment validation successful")
            return {'success': True}
            
        except Exception as e:
            self.add_log(f"Environment validation failed: {e}", "ERROR")
            return {'success': False, 'error': str(e)}
    
    def start_oauth_flow(self):
        """Enhanced OAuth flow start with proper error handling"""
        try:
            # Validate environment first
            env_check = self.validate_environment()
            if not env_check['success']:
                return env_check
            
            self.add_log("Starting Google OAuth 2.0 flow")
            
            # Create OAuth flow using google-auth-oauthlib
            flow = InstalledAppFlow.from_client_config(
                self.client_config,
                scopes=self.SCOPES
            )
            
            # Generate authorization URL
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'  # Force consent to get refresh token
            )
            
            # Store flow in session for completion
            session['oauth_flow_state'] = flow.state
            session['oauth_client_config'] = self.client_config
            
            self.add_log(f"OAuth URL generated successfully: {auth_url[:50]}...")
            
            return {
                'success': True, 
                'auth_url': auth_url,
                'instructions': [
                    "1. Click the authorization URL above",
                    "2. Sign in to your Google account",
                    "3. Grant permissions to the application", 
                    "4. Copy the authorization code",
                    "5. Paste it back here to complete authentication"
                ]
            }
            
        except Exception as e:
            self.add_log(f"OAuth flow start failed: {e}", "ERROR")
            return {'success': False, 'error': f'OAuth flow failed: {str(e)}'}
    
    def complete_oauth_flow(self, auth_code):
        """Enhanced OAuth completion with proper credential handling"""
        try:
            if not auth_code or len(auth_code.strip()) < 10:
                return {'success': False, 'error': 'Invalid authorization code provided'}
            
            auth_code = auth_code.strip()
            self.add_log(f"Completing OAuth with authorization code: {auth_code[:10]}...")
            
            # Recreate flow from session
            client_config = session.get('oauth_client_config')
            if not client_config:
                return {'success': False, 'error': 'OAuth session expired. Please restart the flow.'}
            
            flow = InstalledAppFlow.from_client_config(
                client_config,
                scopes=self.SCOPES
            )
            
            # Exchange authorization code for credentials
            flow.fetch_token(code=auth_code)
            
            # Store credentials
            self.credentials = flow.credentials
            
            # Test Gmail connection
            self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
            
            # Get user profile to verify connection
            profile = self.gmail_service.users().getProfile(userId='me').execute()
            email_address = profile.get('emailAddress', 'Unknown')
            total_messages = profile.get('messagesTotal', 0)
            
            # Store credentials in session for persistence
            session['gmail_credentials'] = {
                'token': self.credentials.token,
                'refresh_token': self.credentials.refresh_token,
                'token_uri': self.credentials.token_uri,
                'client_id': self.credentials.client_id,
                'client_secret': self.credentials.client_secret,
                'scopes': self.credentials.scopes
            }
            
            self.add_log(f"Gmail authentication successful for: {email_address}")
            self.add_log(f"Total messages in mailbox: {total_messages}")
            
            return {
                'success': True, 
                'email': email_address,
                'total_messages': total_messages,
                'scopes_granted': self.credentials.scopes
            }
            
        except Exception as e:
            self.add_log(f"OAuth completion failed: {e}", "ERROR")
            return {'success': False, 'error': f'OAuth completion failed: {str(e)}'}
    
    def restore_credentials_from_session(self):
        """Restore Gmail credentials from session"""
        try:
            creds_data = session.get('gmail_credentials')
            if not creds_data:
                self.add_log("No stored credentials found in session")
                return False
            
            # Recreate credentials object
            self.credentials = Credentials(
                token=creds_data['token'],
                refresh_token=creds_data.get('refresh_token'),
                token_uri=creds_data['token_uri'],
                client_id=creds_data['client_id'],
                client_secret=creds_data['client_secret'],
                scopes=creds_data['scopes']
            )
            
            # Refresh if expired
            if self.credentials.expired and self.credentials.refresh_token:
                self.add_log("Refreshing expired credentials")
                self.credentials.refresh(Request())
                
                # Update session with new token
                session['gmail_credentials']['token'] = self.credentials.token
            
            # Rebuild Gmail service
            self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
            
            # Test connection
            profile = self.gmail_service.users().getProfile(userId='me').execute()
            email = profile.get('emailAddress', 'Unknown')
            
            self.add_log(f"Credentials restored successfully for: {email}")
            return True
            
        except Exception as e:
            self.add_log(f"Failed to restore credentials: {e}", "ERROR")
            self.gmail_service = None
            self.credentials = None
            return False
    
    def get_oauth_status(self):
        """Get current OAuth authentication status"""
        try:
            if not self.gmail_service:
                # Try to restore from session
                if not self.restore_credentials_from_session():
                    return {
                        'authenticated': False,
                        'email': None,
                        'status': 'Not authenticated'
                    }
            
            # Test current connection
            profile = self.gmail_service.users().getProfile(userId='me').execute()
            email = profile.get('emailAddress', 'Unknown')
            
            return {
                'authenticated': True,
                'email': email,
                'status': 'Active connection',
                'total_messages': profile.get('messagesTotal', 0),
                'scopes': self.credentials.scopes if self.credentials else []
            }
            
        except Exception as e:
            self.add_log(f"OAuth status check failed: {e}", "ERROR")
            return {
                'authenticated': False,
                'email': None,
                'status': f'Connection error: {str(e)}'
            }
    
    def disconnect_gmail(self):
        """Disconnect Gmail and clear credentials"""
        try:
            self.gmail_service = None
            self.credentials = None
            
            # Clear session data
            session.pop('gmail_credentials', None)
            session.pop('oauth_flow_state', None)
            session.pop('oauth_client_config', None)
            
            self.add_log("Gmail disconnected successfully")
            return {'success': True, 'message': 'Gmail disconnected'}
            
        except Exception as e:
            self.add_log(f"Disconnect failed: {e}", "ERROR")
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
        """BASIC Gmail scan - enhanced with better error handling"""
        try:
            if not self.gmail_service:
                if not self.restore_credentials_from_session():
                    return {'success': False, 'error': 'Gmail not authenticated. Please complete OAuth first.'}
            
            self.add_log(f"Starting basic Gmail scan (max {max_emails} emails)")
            
            # Enhanced query for VLSI/resume content
            query = 'subject:resume OR subject:CV OR subject:"curriculum vitae" OR subject:VLSI OR subject:"chip design"'
            
            # Get email list
            results = self.gmail_service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_emails
            ).execute()
            
            messages = results.get('messages', [])
            count = len(messages)
            
            self.add_log(f"Basic scan completed: Found {count} emails matching criteria")
            
            return {
                'success': True,
                'emails_found': count,
                'query_used': query,
                'method': 'enhanced_gmail_list',
                'max_scanned': max_emails
            }
            
        except Exception as e:
            self.add_log(f"Gmail scan failed: {e}", "ERROR")
            return {'success': False, 'error': str(e)}

# Initialize enhanced scanner
scanner = EnhancedGmailScanner()

@app.route('/')
def index():
    """Enhanced Railway deployment page with improved OAuth"""
    # Check OAuth status on page load
    oauth_status = scanner.get_oauth_status()
    
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔬 VLSI Resume Scanner - Enhanced OAuth</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh; padding: 20px; color: #333;
            }
            .container { 
                max-width: 1000px; margin: 0 auto; 
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
            .btn:disabled { background: #ccc; cursor: not-allowed; }
            .btn-success { background: #28a745; }
            .btn-success:hover { background: #218838; }
            .btn-danger { background: #dc3545; }
            .btn-danger:hover { background: #c82333; }
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
            .oauth-connected {
                background: #e8f5e8; border: 1px solid #4caf50;
                border-radius: 10px; padding: 15px; margin: 15px 0;
            }
            .oauth-url {
                background: #f5f5f5; padding: 10px; border-radius: 5px;
                word-break: break-all; margin: 10px 0; font-size: 0.9em;
                max-height: 100px; overflow-y: auto;
            }
            .instructions {
                background: #f8f9fa; padding: 15px; border-radius: 5px;
                margin: 10px 0; text-align: left;
            }
            .instructions ol {
                margin-left: 20px;
            }
            .logs {
                background: #f1f1f1; padding: 10px; border-radius: 5px;
                max-height: 300px; overflow-y: auto; font-family: monospace;
                font-size: 0.9em; text-align: left;
            }
            .code-input {
                font-family: monospace; min-width: 300px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔬 VLSI Resume Scanner</h1>
                <p>Railway Deployment + Enhanced Google OAuth</p>
            </div>
            
            <div class="content">
                <div class="status">
                    <h3>✅ Railway Deployment with Enhanced OAuth!</h3>
                    <p>Application with robust Gmail OAuth implementation</p>
                </div>

                <div class="env-status">
                    <h4>🔧 Environment Configuration</h4>
                    <p><strong>Port:</strong> ''' + str(os.environ.get('PORT', 'Not Set')) + '''</p>
                    <p><strong>Google APIs:</strong> ''' + ('✅ Available' if GOOGLE_APIS_AVAILABLE else '❌ Not Installed') + '''</p>
                    <p><strong>OAuth Credentials:</strong> Configured via GUI</p>
                    <p><strong>Admin Password:</strong> ''' + ('✅ Custom' if os.environ.get('ADMIN_PASSWORD') else '⚠️ Default (admin123)') + '''</p>
                </div>

                <div id="auth-section" class="auth-section">
                    <h3>🔐 Admin Authentication</h3>
                    <div class="input-group">
                        <input type="password" id="admin-password" placeholder="Enter admin password" autocomplete="current-password">
                        <button type="button" class="btn" onclick="authenticate()" id="login-btn">🔑 Login</button>
                    </div>
                    <p>Default password: <code>admin123</code> (change via ADMIN_PASSWORD env var)</p>
                    <div id="auth-debug" style="margin-top: 10px; font-size: 0.9em; color: #666;"></div>
                </div>

                <div id="main-content" class="main-content">
                    <h2>🎛️ Enhanced Gmail Scanner with OAuth</h2>
                    <p>Railway deployment successful. Ready for enhanced Gmail scanning with proper OAuth flow.</p>
                    
                    <div class="gmail-section">
                        <h4>📧 Gmail OAuth Authentication</h4>
                        
                        <!-- OAuth Credentials Setup -->
                        <div id="credentials-setup" class="oauth-section">
                            <h5>🔑 Step 1: Configure OAuth Credentials</h5>
                            <p>Enter your Google Cloud Console OAuth credentials:</p>
                            <div id="credentials-status">Loading credentials status...</div>
                            
                            <div id="credentials-form">
                                <div class="input-group">
                                    <input type="text" id="client-id" placeholder="Google Client ID" style="min-width: 400px;">
                                </div>
                                <div class="input-group">
                                    <input type="password" id="client-secret" placeholder="Google Client Secret" style="min-width: 400px;">
                                </div>
                                <button class="btn btn-success" onclick="setupCredentials()">💾 Save Credentials</button>
                                <button class="btn" onclick="clearCredentials()">🗑️ Clear</button>
                            </div>
                            
                            <div class="instructions">
                                <h6>📋 How to get Google OAuth credentials:</h6>
                                <ol>
                                    <li>Go to <a href="https://console.cloud.google.com" target="_blank">Google Cloud Console</a></li>
                                    <li>Create a new project or select existing one</li>
                                    <li>Enable Gmail API in "APIs & Services"</li>
                                    <li>Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"</li>
                                    <li>Choose "Desktop Application" as application type</li>
                                    <li>Copy the Client ID and Client Secret here</li>
                                </ol>
                            </div>
                        </div>
                        
                        <!-- OAuth Status -->
                        <div id="oauth-status">Loading OAuth status...</div>
                        
                        <!-- OAuth Flow -->
                        <div id="oauth-flow" class="oauth-section">
                            <h5>🚀 Step 2: Authenticate with Gmail</h5>
                            <button class="btn btn-success" onclick="startEnhancedOAuth()" id="oauth-btn" disabled>🚀 Start Gmail OAuth</button>
                            
                            <div id="oauth-instructions" class="instructions hidden">
                                <h5>📋 OAuth Setup Instructions</h5>
                                <div id="instruction-list"></div>
                                <p><strong>Authorization URL:</strong></p>
                                <div id="auth-url" class="oauth-url"></div>
                                <div class="input-group">
                                    <input type="text" id="auth-code" class="code-input" placeholder="Paste authorization code here">
                                    <button class="btn" onclick="completeEnhancedOAuth()">✅ Complete OAuth</button>
                                </div>
                            </div>
                        </div>
                        
                        <button class="btn" onclick="basicGmailScan()" id="scan-btn" disabled>📊 Enhanced Gmail Scan</button>
                        <button class="btn btn-danger" onclick="disconnectGmail()" id="disconnect-btn" disabled>🔌 Disconnect Gmail</button>
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
        // Debug function to check if scripts are loading
        console.log('Script loaded successfully');
        
        function authenticate() {
            console.log('Authenticate function called');
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
                    checkCredentialsStatus();
                    checkOAuthStatus();
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

        function checkCredentialsStatus() {
            fetch('/api/gmail/credentials-status')
            .then(r => r.json())
            .then(data => {
                const statusDiv = document.getElementById('credentials-status');
                const oauthBtn = document.getElementById('oauth-btn');
                
                if (data.configured) {
                    statusDiv.innerHTML = `
                        <div class="oauth-connected">
                            <p>✅ <strong>Credentials Configured</strong></p>
                            <p><strong>Client ID:</strong> ${data.client_id_preview}</p>
                            <p><strong>Client Secret:</strong> ${data.has_secret ? '✅ Set' : '❌ Missing'}</p>
                        </div>
                    `;
                    oauthBtn.disabled = false;
                    document.getElementById('credentials-form').style.display = 'none';
                } else {
                    statusDiv.innerHTML = `
                        <div class="oauth-section">
                            <p>❌ <strong>OAuth credentials not configured</strong></p>
                            <p>Please enter your Google Cloud Console credentials below.</p>
                        </div>
                    `;
                    oauthBtn.disabled = true;
                    document.getElementById('credentials-form').style.display = 'block';
                }
            })
            .catch(err => {
                console.error('Credentials status error:', err);
                document.getElementById('credentials-status').innerHTML = '<p style="color: red;">Failed to check credentials status</p>';
            });
        }

        function setupCredentials() {
            const clientId = document.getElementById('client-id').value.trim();
            const clientSecret = document.getElementById('client-secret').value.trim();
            
            if (!clientId || !clientSecret) {
                alert('Please enter both Client ID and Client Secret');
                return;
            }
            
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
                if (data.success) {
                    alert('OAuth credentials configured successfully!');
                    document.getElementById('client-id').value = '';
                    document.getElementById('client-secret').value = '';
                    checkCredentialsStatus();
                    refreshLogs();
                } else {
                    alert('Failed to configure credentials: ' + data.error);
                }
            })
            .catch(err => {
                alert('Failed to save credentials');
                console.error('Credentials setup error:', err);
            });
        }

        function clearCredentials() {
            if (!confirm('Are you sure you want to clear the stored OAuth credentials?')) {
                return;
            }
            
            fetch('/api/gmail/clear-credentials', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('Credentials cleared successfully');
                    document.getElementById('client-id').value = '';
                    document.getElementById('client-secret').value = '';
                    checkCredentialsStatus();
                    checkOAuthStatus();
                    refreshLogs();
                } else {
                    alert('Failed to clear credentials: ' + data.error);
                }
            })
            .catch(err => {
                alert('Failed to clear credentials');
                console.error('Clear credentials error:', err);
            });
        }
            fetch('/api/gmail/oauth-status')
            .then(r => r.json())
            .then(data => {
                const statusDiv = document.getElementById('oauth-status');
                if (data.authenticated) {
                    statusDiv.innerHTML = `
                        <div class="oauth-connected">
                            <h5>✅ Gmail Connected</h5>
                            <p><strong>Email:</strong> ${data.email}</p>
                            <p><strong>Total Messages:</strong> ${data.total_messages || 'Unknown'}</p>
                            <p><strong>Status:</strong> ${data.status}</p>
                        </div>
                    `;
                    document.getElementById('oauth-btn').textContent = '✅ OAuth Complete';
                    document.getElementById('oauth-btn').disabled = true;
                    document.getElementById('scan-btn').disabled = false;
                    document.getElementById('disconnect-btn').disabled = false;
                } else {
                    statusDiv.innerHTML = `
                        <div class="oauth-section">
                            <h5>❌ Gmail Not Connected</h5>
                            <p><strong>Status:</strong> ${data.status}</p>
                        </div>
                    `;
                    document.getElementById('oauth-btn').disabled = false;
                    document.getElementById('scan-btn').disabled = true;
                    document.getElementById('disconnect-btn').disabled = true;
                }
            })
            .catch(err => {
                console.error('OAuth status error:', err);
                document.getElementById('oauth-status').innerHTML = '<p style="color: red;">Failed to check OAuth status</p>';
            });
        }

        function startEnhancedOAuth() {
            document.getElementById('oauth-btn').textContent = '⏳ Starting OAuth...';
            document.getElementById('oauth-btn').disabled = true;
            
            fetch('/api/gmail/start-oauth-enhanced', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('oauth-instructions').classList.remove('hidden');
                    
                    // Show instructions
                    const instructionList = document.getElementById('instruction-list');
                    instructionList.innerHTML = '<ol>' + 
                        data.instructions.map(inst => `<li>${inst}</li>`).join('') + 
                        '</ol>';
                    
                    // Show auth URL
                    document.getElementById('auth-url').innerHTML = 
                        `<a href="${data.auth_url}" target="_blank" style="color: #4a90e2; text-decoration: none;">${data.auth_url}</a>`;
                    
                    document.getElementById('oauth-btn').textContent = '⏳ Waiting for code...';
                } else {
                    alert('Enhanced OAuth start failed: ' + data.error);
                    document.getElementById('oauth-btn').textContent = '🚀 Start Enhanced OAuth';
                    document.getElementById('oauth-btn').disabled = false;
                }
            })
            .catch(err => {
                alert('OAuth request failed');
                console.error('OAuth error:', err);
                document.getElementById('oauth-btn').textContent = '🚀 Start Enhanced OAuth';
                document.getElementById('oauth-btn').disabled = false;
            });
        }

        function completeEnhancedOAuth() {
            const authCode = document.getElementById('auth-code').value.trim();
            if (!authCode) {
                alert('Please enter the authorization code');
                return;
            }
            
            fetch('/api/gmail/complete-oauth-enhanced', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ auth_code: authCode })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert(`Gmail authentication successful!\\nEmail: ${data.email}\\nTotal Messages: ${data.total_messages}`);
                    document.getElementById('oauth-instructions').classList.add('hidden');
                    checkOAuthStatus();
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

        function disconnectGmail() {
            if (!confirm('Are you sure you want to disconnect Gmail? You will need to re-authenticate.')) {
                return;
            }
            
            fetch('/api/gmail/disconnect', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('Gmail disconnected successfully');
                    checkOAuthStatus();
                    document.getElementById('oauth-btn').textContent = '🚀 Start Enhanced OAuth';
                    document.getElementById('oauth-btn').disabled = false;
                    document.getElementById('oauth-instructions').classList.add('hidden');
                    document.getElementById('auth-code').value = '';
                    refreshLogs();
                } else {
                    alert('Disconnect failed: ' + data.error);
                }
            })
            .catch(err => {
                alert('Disconnect request failed');
                console.error('Disconnect error:', err);
            });
        }

        function basicGmailScan() {
            document.getElementById('scan-results').innerHTML = '<p>🔄 Scanning Gmail for resume/VLSI emails...</p>';
            
            fetch('/api/gmail/basic-scan', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('scan-results').innerHTML = 
                        `<div style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 10px 0;">
                            <h5>✅ Enhanced Scan Results</h5>
                            <p><strong>Emails Found:</strong> ${data.emails_found}</p>
                            <p><strong>Query Used:</strong> ${data.query_used}</p>
                            <p><strong>Max Scanned:</strong> ${data.max_scanned}</p>
                            <p><strong>Method:</strong> ${data.method}</p>
                        </div>`;
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
                    <p><strong>OAuth Credentials:</strong> ${data.oauth_credentials_configured ? '✅' : '❌'}</p>
                    <p><strong>Gmail Connected:</strong> ${data.gmail_authenticated ? '✅' : '❌'}</p>
                    <p><strong>OAuth Enhanced:</strong> ${data.oauth_enhanced ? '✅' : '❌'}</p>
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
                    document.getElementById('logs').innerHTML = data.logs.slice(-15).join('<br>');
                }
            })
            .catch(err => {
                console.error('Logs error:', err);
            });
        }

        // Handle Enter key in password field
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM loaded, setting up event listeners...');
            
            const passwordField = document.getElementById('admin-password');
            const loginBtn = document.getElementById('login-btn');
            
            if (passwordField) {
                passwordField.addEventListener('keypress', function(e) {
                    console.log('Key pressed:', e.key);
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        authenticate();
                    }
                });
                console.log('Password field event listener added');
            } else {
                console.error('Password field not found!');
            }
            
            if (loginBtn) {
                loginBtn.addEventListener('click', function(e) {
                    console.log('Login button clicked');
                    e.preventDefault();
                    authenticate();
                });
                console.log('Login button event listener added');
            } else {
                console.error('Login button not found!');
            }
            
            // Test authentication endpoint
            fetch('/api/test')
            .then(r => r.json())
            .then(data => {
                console.log('API test successful:', data);
                document.getElementById('auth-debug').innerHTML = '✅ API connection working';
            })
            .catch(err => {
                console.error('API test failed:', err);
                document.getElementById('auth-debug').innerHTML = '❌ API connection failed: ' + err.message;
            });
        });
        
        // Auto-refresh OAuth status every 30 seconds if authenticated
        setInterval(() => {
            if (document.getElementById('main-content').style.display !== 'none') {
                checkOAuthStatus();
            }
        }, 30000);
        </script>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/api/auth', methods=['POST'])
def api_auth():
    """Railway admin authentication - Enhanced with debugging"""
    try:
        print(f"Auth endpoint hit at {datetime.now()}")
        data = request.get_json()
        print(f"Request data: {data}")
        
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        
        password = data.get('password', '')
        print(f"Password length: {len(password) if password else 0}")
        
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            scanner.add_log("Admin authentication successful")
            print("Authentication successful")
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            scanner.add_log(f"Failed admin authentication attempt with password length: {len(password)}", "WARNING")
            print(f"Authentication failed. Expected: {ADMIN_PASSWORD}, Got: {password}")
            return jsonify({'success': False, 'message': 'Invalid password'})
    except Exception as e:
        error_msg = f"Authentication error: {e}"
        print(error_msg)
        scanner.add_log(error_msg, "ERROR")
        return jsonify({'success': False, 'message': error_msg}), 500

@app.route('/api/system-info')
def api_system_info():
    """Enhanced Railway system information"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        oauth_status = scanner.get_oauth_status()
        
        return jsonify({
            'port': os.environ.get('PORT', 'Not Set'),
            'environment': 'Railway',
            'admin_authenticated': session.get('admin_authenticated', False),
            'google_apis_available': GOOGLE_APIS_AVAILABLE,
            'oauth_credentials_configured': scanner.get_credentials_status()['configured'],
            'gmail_authenticated': oauth_status['authenticated'],
            'oauth_enhanced': True,
            'deployment_status': 'Active with GUI OAuth',
            'timestamp': datetime.now().isoformat(),
            'railway_deployment': True,
            'gmail_email': oauth_status.get('email'),
            'total_logs': len(scanner.logs)
        })
    except Exception as e:
        scanner.add_log(f"System info failed: {e}", "ERROR")
        return jsonify({'error': f'System info failed: {str(e)}'}), 500

# Enhanced Gmail API endpoints with GUI credentials
@app.route('/api/gmail/setup-credentials', methods=['POST'])
def api_gmail_setup_credentials():
    """Setup OAuth credentials via GUI"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        client_id = data.get('client_id', '')
        client_secret = data.get('client_secret', '')
        
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
        
        # Clear from scanner
        scanner.client_config = None
        
        # Clear from session
        session.pop('oauth_client_config', None)
        session.pop('gmail_credentials', None)
        session.pop('oauth_flow_state', None)
        
        # Disconnect Gmail
        scanner.disconnect_gmail()
        
        scanner.add_log("OAuth credentials cleared from GUI")
        return jsonify({'success': True, 'message': 'Credentials cleared successfully'})
    except Exception as e:
        scanner.add_log(f"Clear credentials failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})
@app.route('/api/gmail/start-oauth-enhanced', methods=['POST'])
def api_gmail_start_oauth_enhanced():
    """Start enhanced Gmail OAuth flow"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        result = scanner.start_oauth_flow()
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Enhanced OAuth start failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/complete-oauth-enhanced', methods=['POST'])
def api_gmail_complete_oauth_enhanced():
    """Complete enhanced Gmail OAuth flow"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        auth_code = data.get('auth_code', '')
        result = scanner.complete_oauth_flow(auth_code)
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Enhanced OAuth completion failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/oauth-status')
def api_gmail_oauth_status():
    """Get current Gmail OAuth status"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        status = scanner.get_oauth_status()
        return jsonify(status)
    except Exception as e:
        scanner.add_log(f"OAuth status check failed: {e}", "ERROR")
        return jsonify({'authenticated': False, 'status': f'Error: {str(e)}'})

@app.route('/api/gmail/disconnect', methods=['POST'])
def api_gmail_disconnect():
    """Disconnect Gmail and clear credentials"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        result = scanner.disconnect_gmail()
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Gmail disconnect failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gmail/basic-scan', methods=['POST'])
def api_gmail_basic_scan():
    """Enhanced Gmail scan with better error handling"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        result = scanner.basic_gmail_scan(100)
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"Gmail scan failed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/logs')
def api_logs():
    """Get enhanced activity logs"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        return jsonify({
            'logs': scanner.logs[-25:],  # Last 25 logs
            'total_logs': len(scanner.logs),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/health')
def health_check():
    """Enhanced Railway health check endpoint"""
    oauth_status = scanner.get_oauth_status()
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'VLSI Resume Scanner with Enhanced OAuth',
        'railway_deployment': True,
        'gmail_functionality': GOOGLE_APIS_AVAILABLE,
        'oauth_enhanced': True,
        'gmail_connected': oauth_status['authenticated'],
        'total_logs': len(scanner.logs)
    })

@app.route('/api/test')
def api_test():
    """Enhanced API test endpoint for Railway"""
    return jsonify({
        'message': 'Railway deployment with Enhanced OAuth test successful!',
        'timestamp': datetime.now().isoformat(),
        'status': 'success',
        'railway_environment': True,
        'gmail_apis': GOOGLE_APIS_AVAILABLE,
        'oauth_enhanced': True,
        'features': [
            'Enhanced Google OAuth 2.0 flow',
            'Credential persistence in session',
            'Automatic token refresh',
            'Comprehensive error handling',
            'Real-time OAuth status monitoring'
        ]
    })

# Error handlers - Enhanced
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found', 
        'available_endpoints': [
            '/', '/health', '/api/test', '/api/auth', '/api/system-info',
            '/api/gmail/setup-credentials', '/api/gmail/credentials-status', '/api/gmail/clear-credentials',
            '/api/gmail/start-oauth-enhanced', '/api/gmail/complete-oauth-enhanced',
            '/api/gmail/oauth-status', '/api/gmail/disconnect', '/api/gmail/basic-scan',
            '/api/logs'
        ],
        'railway_deployment': True,
        'oauth_enhanced': True
    }), 404

@app.errorhandler(500)
def internal_error(error):
    scanner.add_log(f"Internal server error: {error}", "ERROR")
    return jsonify({
        'error': 'Internal server error',
        'railway_deployment': True,
        'oauth_enhanced': True
    }), 500

# RAILWAY DEPLOYMENT ENTRY POINT - Enhanced
if __name__ == '__main__':
    # Railway deployment configuration
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    print(f"🚀 Starting VLSI Resume Scanner with GUI-based OAuth on Railway")
    print(f"📊 Port: {port}")
    print(f"🔧 Debug Mode: {debug_mode}")
    print(f"📧 Google APIs Available: {GOOGLE_APIS_AVAILABLE}")
    print(f"🔐 OAuth Mode: GUI-based (no environment variables needed)")
    
    # Log startup
    scanner.add_log("Application starting up with GUI-based OAuth")
    
    app.run(
        debug=debug_mode, 
        host='0.0.0.0', 
        port=port
    )
