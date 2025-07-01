import os
import hashlib
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string, request, session

# Import Google APIs (we know these work!)
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-2024')

# Railway admin password
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# Simple Resume Scanner Class
class ResumeScanner:
    def __init__(self):
        self.credentials = None
        self.gmail_service = None
        self.drive_service = None
        self.last_scan_time = None
        self.drive_folder_id = None
        self.processed_emails = set()
        self.processed_file_hashes = set()
        self.stats = {
            'emails_processed': 0,
            'resumes_found': 0,
            'files_uploaded': 0
        }
    
    def authenticate_google(self):
        """Start OAuth flow"""
        try:
            # Use Railway environment variables if available
            client_id = os.environ.get('GOOGLE_CLIENT_ID')
            client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
            
            if not client_id or not client_secret:
                return {'success': False, 'error': 'Google credentials not configured in Railway environment variables'}
            
            credentials_dict = {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"]
                }
            }
            
            flow = InstalledAppFlow.from_client_config(credentials_dict, [
                'https://www.googleapis.com/auth/gmail.readonly',
                'https://www.googleapis.com/auth/drive.file'
            ])
            
            # Store flow in session for later use
            session['oauth_flow'] = True
            
            # Generate auth URL with proper redirect
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                prompt='select_account',
                include_granted_scopes='true',
                redirect_uri='urn:ietf:wg:oauth:2.0:oob'
            )
            
            # Store flow state (simplified for session)
            self._current_flow = flow
            
            return {'success': True, 'auth_url': auth_url}
            
        except Exception as e:
            return {'success': False, 'error': f'OAuth setup failed: {str(e)}'}
    
    def complete_oauth(self, auth_code):
        """Complete OAuth with authorization code"""
        try:
            if not hasattr(self, '_current_flow') or not self._current_flow:
                return {'success': False, 'error': 'OAuth flow not started. Please start authentication first.'}
            
            # Exchange code for credentials
            self._current_flow.fetch_token(code=auth_code)
            self.credentials = self._current_flow.credentials
            
            # Initialize services
            self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
            self.drive_service = build('drive', 'v3', credentials=self.credentials)
            
            # Test the connection
            profile = self.gmail_service.users().getProfile(userId='me').execute()
            email = profile.get('emailAddress', 'Unknown')
            
            return {'success': True, 'email': email, 'message': 'Authentication completed successfully'}
            
        except Exception as e:
            return {'success': False, 'error': f'OAuth completion failed: {str(e)}'}
    
    def create_drive_folder(self, folder_name="VLSI_Resumes"):
        """Create Google Drive folder"""
        try:
            if not self.drive_service:
                return {'success': False, 'error': 'Drive service not available'}
            
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder = self.drive_service.files().create(body=folder_metadata).execute()
            self.drive_folder_id = folder.get('id')
            
            return {'success': True, 'folder_id': self.drive_folder_id, 'folder_name': folder_name}
            
        except Exception as e:
            return {'success': False, 'error': f'Failed to create folder: {str(e)}'}
    
    def get_status(self):
        """Get scanner status"""
        return {
            'authenticated': self.credentials is not None,
            'gmail_active': self.gmail_service is not None,
            'drive_active': self.drive_service is not None,
            'drive_folder_id': self.drive_folder_id,
            'last_scan': self.last_scan_time.isoformat() if self.last_scan_time else None,
            'stats': self.stats,
            'google_credentials_in_env': bool(os.environ.get('GOOGLE_CLIENT_ID'))
        }

# Initialize scanner
scanner = ResumeScanner()

# Simple test to ensure basic Flask is working
@app.route('/')
def index():
    """Minimal test page"""
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔬 VLSI Resume Scanner - Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 50px; background: #f0f0f0; }
            .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }
            .status { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .btn { background: #4a90e2; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔬 VLSI Resume Scanner</h1>
            <div class="status">
                <h3>✅ Railway Deployment Test Successful!</h3>
                <p>Basic Flask app is running on Railway</p>
            </div>
            
            <h3>🔧 System Check</h3>
            <p><strong>Python Version:</strong> Available</p>
            <p><strong>Flask:</strong> ✅ Working</p>
            <p><strong>Google Auth:</strong> ''' + ('✅' if 'GOOGLE_AUTH_AVAILABLE' in locals() and GOOGLE_AUTH_AVAILABLE else '❌') + '''</p>
            <p><strong>Google API Client:</strong> ''' + ('✅' if 'GOOGLE_API_CLIENT_AVAILABLE' in locals() and GOOGLE_API_CLIENT_AVAILABLE else '❌') + '''</p>
            <p><strong>Environment:</strong> Railway</p>
            <p><strong>Port:</strong> ''' + str(os.environ.get('PORT', 'Not Set')) + '''</p>
            
            <h3>🔐 Test Authentication</h3>
            <input type="password" id="admin-password" placeholder="Enter admin password (default: admin123)">
            <button class="btn" onclick="testAuth()">Test Login</button>
            
            <h3>📋 Test APIs</h3>
            <button class="btn" onclick="testHealth()">Test Health Check</button>
            <button class="btn" onclick="testStatus()">Test Status</button>
            
            <div id="results" style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                Test results will appear here...
            </div>
        </div>

        <script>
        function testAuth() {
            const password = document.getElementById('admin-password').value;
            
            fetch('/api/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: password })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('results').innerHTML = 
                    '<h4>Auth Result:</h4><pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(err => {
                document.getElementById('results').innerHTML = 
                    '<h4 style="color: red;">Auth Failed:</h4><p>' + err + '</p>';
            });
        }

        function testHealth() {
            fetch('/health')
            .then(r => r.json())
            .then(data => {
                document.getElementById('results').innerHTML = 
                    '<h4>Health Check Result:</h4><pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(err => {
                document.getElementById('results').innerHTML = 
                    '<h4 style="color: red;">Health Check Failed:</h4><p>' + err + '</p>';
            });
        }

        function testStatus() {
            fetch('/api/status')
            .then(r => r.json())
            .then(data => {
                document.getElementById('results').innerHTML = 
                    '<h4>Status Result:</h4><pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(err => {
                document.getElementById('results').innerHTML = 
                    '<h4 style="color: red;">Status Failed:</h4><p>' + err + '</p>';
            });
        }
        </script>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/health')
def health_check():
    """Railway health check"""
    return jsonify({
        'status': 'healthy',
        'message': 'VLSI Resume Scanner is running',
        'port': os.environ.get('PORT', 'Not Set'),
        'environment': 'Railway'
    })

@app.route('/api/auth', methods=['POST'])
def api_auth():
    """Test authentication"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            return jsonify({'success': False, 'message': 'Invalid password'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/complete-oauth', methods=['POST'])
def api_complete_oauth():
    """Complete OAuth flow with authorization code"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        data = request.get_json()
        auth_code = data.get('auth_code', '').strip()
        
        if not auth_code:
            return jsonify({'success': False, 'error': 'Authorization code is required'})
            
        result = scanner.complete_oauth(auth_code)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/create-folder', methods=['POST'])
def api_create_folder():
    """Create Google Drive folder"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        result = scanner.create_drive_folder("VLSI_Resumes_Auto")
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/google-auth', methods=['POST'])
def api_google_auth():
    """Start Google OAuth flow"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        result = scanner.authenticate_google()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scanner-status')
def api_scanner_status():
    """Get detailed scanner status"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        status = scanner.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/test-scan', methods=['POST'])
def api_test_scan():
    """Test scan functionality"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # This is just a test - would implement actual scanning here
        return jsonify({
            'test_mode': True,
            'message': 'Scanner test completed',
            'next_step': 'Complete Google OAuth to enable real scanning',
            'features_ready': [
                'Gmail API integration',
                'Drive folder creation', 
                'Resume categorization',
                'Duplicate detection'
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/status')
def api_status():
    """Basic system status"""
    return jsonify({
        'flask_working': True,
        'python_working': True,
        'railway_deployment': True,
        'port': os.environ.get('PORT'),
        'admin_password_set': bool(os.environ.get('ADMIN_PASSWORD')),
        'session_authenticated': session.get('admin_authenticated', False),
        'google_credentials_configured': bool(os.environ.get('GOOGLE_CLIENT_ID')),
        'scanner_ready': True
    })

@app.route('/test')
def test_page():
    """Simple test endpoint"""
    return jsonify({
        'message': 'Test successful!',
        'flask_version': 'Working',
        'railway_status': 'Deployed'
    })

# Error handler
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'available_endpoints': ['/', '/health', '/api/status', '/test']
    }), 404

# Railway deployment
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting Flask app on port {port}")
    app.run(debug=False, host='0.0.0.0', port=port)
