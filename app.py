import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-2024')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

@app.route('/')
def index():
    """Simple test page to debug login issue"""
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔧 Login Debug Test</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 600px; 
                margin: 50px auto; 
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .input-group {
                margin: 20px 0;
            }
            input {
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                width: 300px;
            }
            button {
                padding: 12px 24px;
                background: #007bff;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                margin-left: 10px;
            }
            button:hover {
                background: #0056b3;
            }
            .debug {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                font-family: monospace;
                font-size: 14px;
            }
            .hidden { display: none; }
            .success {
                background: #d4edda;
                color: #155724;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔧 Login Debug Test</h1>
            <p>Simple test to debug login functionality</p>
            
            <div id="auth-section">
                <h3>🔐 Test Login</h3>
                <div class="input-group">
                    <input type="password" id="password" placeholder="Enter password (default: admin123)">
                    <button onclick="testLogin()">Login</button>
                </div>
                <button onclick="testAPI()">Test API</button>
                <button onclick="testConsole()">Test Console</button>
            </div>
            
            <div id="success-section" class="success hidden">
                <h3>✅ Login Successful!</h3>
                <p>You are now authenticated.</p>
                <button onclick="logout()">Logout</button>
            </div>
            
            <div class="debug" id="debug-output">
                Debug output will appear here...
            </div>
        </div>

        <script>
            function log(message) {
                const debugDiv = document.getElementById('debug-output');
                const timestamp = new Date().toLocaleTimeString();
                debugDiv.innerHTML += `[${timestamp}] ${message}<br>`;
                console.log(message);
            }

            function testConsole() {
                log("✅ JavaScript is working!");
                log("✅ Console function is working!");
                alert("Console test successful!");
            }

            function testAPI() {
                log("🔄 Testing API connection...");
                
                fetch('/api/test-simple')
                .then(response => {
                    log(`📡 Response status: ${response.status}`);
                    return response.json();
                })
                .then(data => {
                    log(`✅ API test successful: ${JSON.stringify(data)}`);
                })
                .catch(error => {
                    log(`❌ API test failed: ${error.message}`);
                });
            }

            function testLogin() {
                log("🔄 Starting login test...");
                
                const password = document.getElementById('password').value;
                log(`📝 Password length: ${password.length}`);
                
                if (!password) {
                    log("❌ No password entered");
                    alert("Please enter a password");
                    return;
                }
                
                log("📡 Sending authentication request...");
                
                const requestData = { password: password };
                log(`📤 Request data: ${JSON.stringify(requestData)}`);
                
                fetch('/api/auth-simple', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(requestData)
                })
                .then(response => {
                    log(`📡 Response status: ${response.status}`);
                    log(`📡 Response headers: ${JSON.stringify([...response.headers])}`);
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    log(`📥 Response data: ${JSON.stringify(data)}`);
                    
                    if (data.success) {
                        log("✅ Authentication successful!");
                        document.getElementById('auth-section').classList.add('hidden');
                        document.getElementById('success-section').classList.remove('hidden');
                    } else {
                        log(`❌ Authentication failed: ${data.message}`);
                        alert(`Authentication failed: ${data.message}`);
                    }
                })
                .catch(error => {
                    log(`❌ Request failed: ${error.message}`);
                    alert(`Login failed: ${error.message}`);
                });
            }

            function logout() {
                log("🔄 Logging out...");
                document.getElementById('auth-section').classList.remove('hidden');
                document.getElementById('success-section').classList.add('hidden');
                document.getElementById('password').value = '';
            }

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                log("🚀 Page loaded successfully");
                log("🔧 Current admin password: ''' + ADMIN_PASSWORD + '''");
                
                // Test basic functionality
                setTimeout(() => {
                    testAPI();
                }, 1000);
            });

            // Handle Enter key
            document.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    testLogin();
                }
            });
        </script>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/api/test-simple')
def api_test_simple():
    """Simple API test"""
    return jsonify({
        'status': 'success',
        'message': 'API is working',
        'timestamp': datetime.now().isoformat(),
        'admin_password_set': bool(ADMIN_PASSWORD)
    })

@app.route('/api/auth-simple', methods=['POST'])
def api_auth_simple():
    """Simple authentication test"""
    try:
        print(f"=== AUTH REQUEST ===")
        print(f"Time: {datetime.now()}")
        print(f"Method: {request.method}")
        print(f"Content-Type: {request.content_type}")
        print(f"Headers: {dict(request.headers)}")
        
        data = request.get_json()
        print(f"JSON Data: {data}")
        
        if not data:
            print("❌ No JSON data received")
            return jsonify({'success': False, 'message': 'No data received'}), 400
        
        password = data.get('password', '')
        print(f"Password received: '{password}' (length: {len(password)})")
        print(f"Expected password: '{ADMIN_PASSWORD}' (length: {len(ADMIN_PASSWORD)})")
        print(f"Passwords match: {password == ADMIN_PASSWORD}")
        
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            print("✅ Authentication successful")
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            print("❌ Authentication failed")
            return jsonify({'success': False, 'message': 'Invalid password'})
            
    except Exception as e:
        print(f"❌ Exception occurred: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting simple login test on port {port}")
    print(f"🔑 Admin password: '{ADMIN_PASSWORD}'")
    
    app.run(
        debug=True, 
        host='0.0.0.0', 
        port=port
    )
