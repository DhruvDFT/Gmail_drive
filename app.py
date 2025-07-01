# Extract attachments
                            attachments = self.extract_attachments(email_data['payload'], message['id'])
                            email_info['attachments'] = attachments
                            
                            # Check for duplicates BEFORE processing
                            duplicate_check = self.check_duplicate_resume(email_info)
                            email_info.update(duplicate_check)
                            
                            # Skip processing if it's a duplicate (unless we want to log duplicates)
                            if duplicate_check['is_duplicate'] and duplicate_check['confidence'] > 80:
                                self.add_log(f"🔄 Duplicate resume detected: {email_info['subject'][:50]} - {duplicate_check['reason']}", 'warning')
                                
                                # Save duplicate info to special folder
                                duplicate_folder_id = self.stats['drive_folders'].get('duplicates')
                                if duplicate_folder_id:
                                    self.save_duplicate_report(email_info, duplicate_check)
                                
                                # Add to processed but skip main processing
                                self.stats['processed_email_ids'].add(message['id'])
                                continue
                            
                            # Analyze resume content with enhanced categorization
                            analysis = self.analyze_resume_content(
                                email_info['subject'], 
                                email_info['body_preview'], 
                                attachments
                            )
                            
                            email_info.update(analysis)
                            all_emails.append(email_info)
                            
                            # Process resume if it meets criteria
                            if analysis['vlsi_relevant'] or attachments or analysis['score'] > 5:
                                # Determine target folder based on domain and subdomain
                                target_folder = self.get_target_folder(analysis)
                                
                                # Download and save attachments
                                saved_attachments = self.download_and_save_attachments(
                                    message['id'], 
                                    attachments, 
                                    target_folder,
                                    analysis
                                )
                                email_info['saved_attachments']import os
import sys
import json
import logging
import threading
import time
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify, session

# Try to import Google API libraries
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload
    import io
    GOOGLE_APIS_AVAILABLE = True
except ImportError:
    GOOGLE_APIS_AVAILABLE = False

# Try to import PDF processing
try:
    import PyPDF2
    PDF_PROCESSING_AVAILABLE = True
except ImportError:
    try:
        import pypdf as PyPDF2
        PDF_PROCESSING_AVAILABLE = True
    except ImportError:
        PDF_PROCESSING_AVAILABLE = False

# Try to import DOC processing
try:
    from docx import Document
    DOCX_PROCESSING_AVAILABLE = True
except ImportError:
    DOCX_PROCESSING_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-2024')

# Configuration
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/spreadsheets'
]

# RAILWAY FIX 1: Ensure proper logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    stream=sys.stdout
)

# RAILWAY FIX 2: Set proper timeouts and buffering
sys.stdout.reconfigure(line_buffering=True)

class VLSIResumeScanner:
    """VLSI Resume Scanner with Google Integration and Auto-Sync"""
    
    def __init__(self):
        self.credentials = None
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        self.logs = []
        self.max_logs = 100
        self.stats = {
            'total_emails': 0,
            'resumes_found': 0,
            'last_scan_time': None,
            'last_full_scan': None,
            'processing_errors': 0,
            'auto_sync_active': False,
            'processed_email_ids': set(),
            'drive_folders': {}
        }
        self.current_user_email = None
        self._oauth_flow = None
        self.auto_sync_thread = None
        self.stop_auto_sync = False
        
        # Drive folder structure
        self.folder_structure = {
            'VLSI_Resumes': 'Main folder for all VLSI resumes',
            'High_Priority': 'Resumes with VLSI keywords and experience',
            'Medium_Priority': 'General resumes with some relevance',
            'Low_Priority': 'Basic resumes requiring review',
            'Attachments': 'All resume attachments',
            'Processed': 'Already processed emails metadata'
        }
        
        self.add_log("🚀 VLSI Resume Scanner initialized with auto-sync capabilities", 'info')
        
    def add_log(self, message: str, level: str = 'info'):
        """Enhanced logging for Railway"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }
        self.logs.append(log_entry)
        
        # Keep only recent logs
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
        
        # RAILWAY FIX 7: Ensure logs appear in Railway dashboard
        if level == 'error':
            app.logger.error(f"[{timestamp}] {message}")
            logging.error(f"[{timestamp}] {message}")
        elif level == 'warning':
            app.logger.warning(f"[{timestamp}] {message}")
            logging.warning(f"[{timestamp}] {message}")
        else:
            app.logger.info(f"[{timestamp}] {message}")
            logging.info(f"[{timestamp}] {message}")

    def get_system_status(self) -> dict:
        """Get current system status"""
        return {
            'google_apis_available': GOOGLE_APIS_AVAILABLE,
            'pdf_processing_available': PDF_PROCESSING_AVAILABLE,
            'docx_processing_available': DOCX_PROCESSING_AVAILABLE,
            'gmail_service_active': self.gmail_service is not None,
            'drive_service_active': self.drive_service is not None,
            'sheets_service_active': self.sheets_service is not None,
            'current_user': self.current_user_email,
            'stats': self.stats,
            'recent_logs': self.logs[-10:] if self.logs else [],
            'auto_sync_status': {
                'active': self.stats['auto_sync_active'],
                'last_full_scan': self.stats['last_full_scan'],
                'processed_emails': len(self.stats['processed_email_ids']),
                'drive_folders': self.stats['drive_folders']
            },
            'environment_check': {
                'has_client_id': bool(os.environ.get('GOOGLE_CLIENT_ID')) or bool(session.get('google_client_id')),
                'has_client_secret': bool(os.environ.get('GOOGLE_CLIENT_SECRET')) or bool(session.get('google_client_secret')),
                'has_project_id': bool(os.environ.get('GOOGLE_PROJECT_ID')) or bool(session.get('google_project_id')),
                'admin_password_set': bool(os.environ.get('ADMIN_PASSWORD'))
            }
        }

    def save_credentials(self, client_id: str, client_secret: str, project_id: str):
        """Save credentials to session"""
        try:
            session['google_client_id'] = client_id
            session['google_client_secret'] = client_secret
            session['google_project_id'] = project_id
            
            self.add_log("✅ Google credentials saved to session", 'info')
            return {'success': True, 'message': 'Credentials saved successfully'}
        except Exception as e:
            self.add_log(f"❌ Failed to save credentials: {e}", 'error')
            return {'success': False, 'error': str(e)}

    def start_oauth_flow(self):
        """Start OAuth authentication flow - ULTIMATE FIX VERSION"""
        try:
            if not GOOGLE_APIS_AVAILABLE:
                return {'success': False, 'error': 'Google APIs not available'}
                
            # Get credentials from environment or session
            client_id = os.environ.get('GOOGLE_CLIENT_ID') or session.get('google_client_id')
            client_secret = os.environ.get('GOOGLE_CLIENT_SECRET') or session.get('google_client_secret')
            
            if not client_id or not client_secret:
                return {'success': False, 'error': 'OAuth credentials not configured'}
            
            # ULTIMATE FIX: Use manual URL construction to avoid oauthlib conflicts
            try:
                import urllib.parse
                
                # Build OAuth URL manually - this eliminates ALL redirect_uri conflicts
                params = {
                    'client_id': client_id,
                    'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
                    'scope': ' '.join(SCOPES),
                    'response_type': 'code',
                    'access_type': 'offline',
                    'prompt': 'select_account'
                }
                
                auth_url = 'https://accounts.google.com/o/oauth2/auth?' + urllib.parse.urlencode(params)
                
                # Store credentials for later use
                session['oauth_client_id'] = client_id
                session['oauth_client_secret'] = client_secret
                
                self.add_log("✅ Manual OAuth URL generated successfully", 'info')
                
                return {
                    'success': True, 
                    'auth_url': auth_url,
                    'message': 'Please visit the authorization URL and enter the code',
                    'method': 'manual'
                }
                
            except Exception as manual_error:
                self.add_log(f"❌ Manual URL generation failed: {manual_error}", 'error')
                
                # FALLBACK: Try the original method with extra safety
                try:
                    # Clear any existing flow
                    self._oauth_flow = None
                    
                    # Create minimal credentials config
                    credentials_dict = {
                        "installed": {
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                            "token_uri": "https://oauth2.googleapis.com/token"
                        }
                    }
                    
                    # Create flow with explicit redirect_uri parameter
                    flow = InstalledAppFlow.from_client_config(
                        credentials_dict, 
                        SCOPES, 
                        redirect_uri='urn:ietf:wg:oauth:2.0:oob'
                    )
                    
                    # Generate URL WITHOUT specifying redirect_uri again
                    auth_url, _ = flow.authorization_url(
                        access_type='offline',
                        prompt='select_account'
                    )
                    
                    self._oauth_flow = flow
                    self.add_log("✅ Fallback OAuth flow created", 'info')
                    
                    return {
                        'success': True, 
                        'auth_url': auth_url,
                        'message': 'Please visit the authorization URL and enter the code',
                        'method': 'fallback'
                    }
                    
                except Exception as fallback_error:
                    self.add_log(f"❌ All OAuth methods failed: {fallback_error}", 'error')
                    return {'success': False, 'error': 'OAuth setup failed - please check credentials'}
            
        except Exception as e:
            error_msg = str(e)
            self.add_log(f"❌ OAuth flow failed: {error_msg}", 'error')
            return {'success': False, 'error': f'OAuth setup failed: {error_msg}'}

    def complete_oauth_flow(self, auth_code: str):
        """Complete OAuth flow - ULTIMATE FIX VERSION"""
        try:
            if not auth_code or not auth_code.strip():
                return {'success': False, 'error': 'Authorization code is required'}
            
            auth_code = auth_code.strip()
            self.add_log(f"🔄 Processing auth code: {auth_code[:10]}...", 'info')
            
            # Get stored credentials
            client_id = session.get('oauth_client_id') or os.environ.get('GOOGLE_CLIENT_ID')
            client_secret = session.get('oauth_client_secret') or os.environ.get('GOOGLE_CLIENT_SECRET')
            
            if not client_id or not client_secret:
                return {'success': False, 'error': 'OAuth credentials not found - please restart authentication'}
            
            # ULTIMATE FIX: Manual token exchange to avoid oauthlib conflicts
            try:
                import urllib.parse
                import urllib.request
                import json
                
                # Manual token exchange
                token_data = {
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'code': auth_code,
                    'grant_type': 'authorization_code',
                    'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob'
                }
                
                token_request = urllib.request.Request(
                    'https://oauth2.googleapis.com/token',
                    data=urllib.parse.urlencode(token_data).encode('utf-8'),
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                with urllib.request.urlopen(token_request) as response:
                    token_response = json.loads(response.read().decode('utf-8'))
                
                if 'access_token' not in token_response:
                    raise Exception('No access token in response')
                
                # Create credentials object manually
                self.credentials = Credentials(
                    token=token_response.get('access_token'),
                    refresh_token=token_response.get('refresh_token'),
                    token_uri='https://oauth2.googleapis.com/token',
                    client_id=client_id,
                    client_secret=client_secret,
                    scopes=SCOPES
                )
                
                self.add_log("✅ Manual token exchange successful", 'info')
                
            except Exception as manual_error:
                self.add_log(f"❌ Manual token exchange failed: {manual_error}", 'error')
                
                # FALLBACK: Try with existing flow if available
                if self._oauth_flow:
                    try:
                        self._oauth_flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
                        self._oauth_flow.fetch_token(code=auth_code)
                        self.credentials = self._oauth_flow.credentials
                        self.add_log("✅ Fallback token exchange successful", 'info')
                    except Exception as fallback_error:
                        self.add_log(f"❌ Fallback token exchange failed: {fallback_error}", 'error')
                        return {'success': False, 'error': f'Token exchange failed: {str(fallback_error)}'}
                else:
                    return {'success': False, 'error': f'Manual token exchange failed: {str(manual_error)}'}
            
            # Test services one by one
            services_status = {}
            email = 'Unknown'
            
            # Test Gmail
            try:
                self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
                result = self.gmail_service.users().getProfile(userId='me').execute()
                email = result.get('emailAddress', 'Unknown')
                services_status['gmail'] = '✅'
                self.add_log(f"✅ Gmail service active for: {email}", 'info')
            except Exception as gmail_error:
                services_status['gmail'] = '❌'
                self.add_log(f"❌ Gmail service failed: {gmail_error}", 'error')
            
            # Test Drive
            try:
                self.drive_service = build('drive', 'v3', credentials=self.credentials)
                self.drive_service.about().get(fields='user').execute()
                services_status['drive'] = '✅'
                self.add_log("✅ Drive service active", 'info')
                
                # Setup drive folders after successful connection
                self.setup_drive_folders()
                
            except Exception as drive_error:
                services_status['drive'] = '❌'
                self.add_log(f"❌ Drive service failed: {drive_error}", 'error')
            
            # Test Sheets
            try:
                self.sheets_service = build('sheets', 'v4', credentials=self.credentials)
                services_status['sheets'] = '✅'
                self.add_log("✅ Sheets service active", 'info')
            except Exception as sheets_error:
                services_status['sheets'] = '❌'
                self.add_log(f"❌ Sheets service failed: {sheets_error}", 'error')
            
            self.current_user_email = email
            
            # Clean up session
            session.pop('oauth_client_id', None)
            session.pop('oauth_client_secret', None)
            
            # Success with detailed status
            success_message = f"Authentication completed! Services: Gmail {services_status.get('gmail', '❌')}, Drive {services_status.get('drive', '❌')}, Sheets {services_status.get('sheets', '❌')}"
            self.add_log(success_message, 'info')
            
            return {
                'success': True, 
                'email': email, 
                'message': success_message,
                'services': services_status
            }
                
        except Exception as e:
            error_msg = str(e)
            self.add_log(f"❌ OAuth completion failed: {error_msg}", 'error')
            return {'success': False, 'error': f'Authentication failed: {error_msg}'}

    def setup_drive_folders(self):
        """Setup Google Drive folder structure for organizing resumes"""
        try:
            if not self.drive_service:
                return {'success': False, 'error': 'Drive service not available'}
            
            self.add_log("📁 Setting up Google Drive folder structure", 'info')
            
            # Check if main folder exists
            main_folder_name = 'VLSI_Resume_Scanner'
            query = f"name='{main_folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            results = self.drive_service.files().list(q=query).execute()
            
            if results.get('files'):
                main_folder_id = results['files'][0]['id']
                self.add_log(f"✅ Found existing main folder: {main_folder_id}", 'info')
            else:
                # Create main folder
                main_folder_metadata = {
                    'name': main_folder_name,
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                main_folder = self.drive_service.files().create(body=main_folder_metadata).execute()
                main_folder_id = main_folder.get('id')
                self.add_log(f"✅ Created main folder: {main_folder_id}", 'info')
            
            self.stats['drive_folders']['main'] = main_folder_id
            
            # Create subfolders
            subfolders = {
                'High_Priority_VLSI': 'Resumes with VLSI/semiconductor experience',
                'Medium_Priority_Technical': 'Technical resumes with relevant skills',
                'Low_Priority_General': 'General resumes requiring review',
                'Resume_Attachments': 'All downloaded resume files',
                'Email_Metadata': 'Processed email information'
            }
            
            for folder_name, description in subfolders.items():
                query = f"name='{folder_name}' and parents in '{main_folder_id}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
                results = self.drive_service.files().list(q=query).execute()
                
                if results.get('files'):
                    folder_id = results['files'][0]['id']
                    self.add_log(f"✅ Found existing subfolder: {folder_name}", 'info')
                else:
                    folder_metadata = {
                        'name': folder_name,
                        'parents': [main_folder_id],
                        'mimeType': 'application/vnd.google-apps.folder'
                    }
                    folder = self.drive_service.files().create(body=folder_metadata).execute()
                    folder_id = folder.get('id')
                    self.add_log(f"✅ Created subfolder: {folder_name}", 'info')
                
                self.stats['drive_folders'][folder_name.lower()] = folder_id
            
            self.add_log("✅ Google Drive folder structure setup complete", 'info')
            return {'success': True, 'folders': self.stats['drive_folders']}
            
        except Exception as e:
            self.add_log(f"❌ Drive folder setup failed: {e}", 'error')
            return {'success': False, 'error': str(e)}

    def analyze_resume_content(self, email_subject: str, email_body: str, attachments: list) -> dict:
        """Advanced resume analysis with domain categorization, experience levels, and duplicate detection"""
        try:
            score = 0
            experience_level = 'entry'
            domain = 'general'
            subdomain = 'unknown'
            keywords_found = []
            
            # Combine all text for analysis
            all_text = f"{email_subject} {email_body}".lower()
            for attachment in attachments:
                all_text += f" {attachment.get('filename', '')}".lower()
            
            # VLSI/Semiconductor Domain Keywords with subdomains
            vlsi_domains = {
                'digital_design': {
                    'keywords': ['digital design', 'rtl', 'verilog', 'vhdl', 'system verilog', 'synthesis', 'verification', 'dft', 'timing analysis', 'sta', 'place and route', 'pnr'],
                    'score': 8,
                    'subdomains': {
                        'rtl_design': ['rtl', 'register transfer level', 'rtl design', 'rtl coding'],
                        'verification': ['verification', 'testbench', 'uvm', 'ovm', 'sve', 'assertions'],
                        'synthesis': ['synthesis', 'dc', 'design compiler', 'genus', 'logic synthesis'],
                        'timing': ['timing', 'sta', 'static timing analysis', 'primetime', 'tempus'],
                        'dft': ['dft', 'design for test', 'scan', 'atpg', 'bist', 'jtag']
                    }
                },
                'analog_design': {
                    'keywords': ['analog design', 'mixed signal', 'rf', 'pll', 'adc', 'dac', 'opamp', 'ldo', 'bandgap', 'oscillator', 'spice', 'cadence', 'spectre'],
                    'score': 8,
                    'subdomains': {
                        'rf_design': ['rf', 'radio frequency', 'microwave', 'antenna', 'mixer', 'lna'],
                        'power_management': ['pmu', 'power management', 'ldo', 'dc-dc', 'buck', 'boost'],
                        'data_converters': ['adc', 'dac', 'converter', 'sigma delta', 'sar', 'pipeline'],
                        'analog_mixed_signal': ['ams', 'mixed signal', 'analog', 'opamp', 'comparator']
                    }
                },
                'physical_design': {
                    'keywords': ['physical design', 'place and route', 'pnr', 'floorplan', 'cts', 'clock tree', 'routing', 'innovus', 'icc', 'encounter'],
                    'score': 7,
                    'subdomains': {
                        'floorplanning': ['floorplan', 'floor planning', 'placement', 'macro placement'],
                        'routing': ['routing', 'global routing', 'detail routing', 'clock routing'],
                        'cts': ['cts', 'clock tree synthesis', 'clock distribution', 'skew'],
                        'sign_off': ['sign off', 'signoff', 'drc', 'lvs', 'antenna', 'em', 'ir drop']
                    }
                },
                'memory_design': {
                    'keywords': ['memory design', 'sram', 'dram', 'flash', 'memory compiler', 'bit cell', 'sense amplifier', 'decoder'],
                    'score': 8,
                    'subdomains': {
                        'sram': ['sram', 'static ram', 'cache memory', 'register file'],
                        'dram': ['dram', 'dynamic ram', 'ddr', 'sdram', 'memory controller'],
                        'flash': ['flash', 'nand', 'nor', 'eeprom', 'non-volatile'],
                        'memory_interface': ['memory interface', 'ddr controller', 'memory subsystem']
                    }
                },
                'asic_design': {
                    'keywords': ['asic', 'soc', 'system on chip', 'chip design', 'silicon', 'tape out', 'foundry', 'process technology'],
                    'score': 7,
                    'subdomains': {
                        'soc_design': ['soc', 'system on chip', 'subsystem', 'integration'],
                        'chip_arch': ['architecture', 'microarchitecture', 'system architecture'],
                        'silicon': ['silicon', 'fab', 'foundry', 'process', 'technology node'],
                        'validation': ['silicon validation', 'post silicon', 'bring up', 'debug']
                    }
                },
                'fpga_design': {
                    'keywords': ['fpga', 'xilinx', 'altera', 'intel psg', 'vivado', 'quartus', 'programmable logic'],
                    'score': 6,
                    'subdomains': {
                        'fpga_dev': ['fpga development', 'programmable logic', 'reconfigurable'],
                        'fpga_tools': ['vivado', 'quartus', 'ise', 'fpga tools'],
                        'embedded_fpga': ['embedded fpga', 'soft core', 'hard core', 'ip core']
                    }
                }
            }
            
            # Software/Firmware Domain
            software_domains = {
                'embedded_software': {
                    'keywords': ['embedded software', 'firmware', 'microcontroller', 'mcu', 'embedded c', 'rtos', 'freertos'],
                    'score': 5,
                    'subdomains': {
                        'firmware': ['firmware', 'embedded firmware', 'bootloader', 'bsp'],
                        'rtos': ['rtos', 'real time os', 'freertos', 'threadx', 'ucos'],
                        'drivers': ['device drivers', 'hal', 'bsp', 'peripheral drivers'],
                        'protocols': ['i2c', 'spi', 'uart', 'can', 'ethernet', 'usb']
                    }
                },
                'software_engineering': {
                    'keywords': ['software engineer', 'python', 'c++', 'java', 'software development', 'programming'],
                    'score': 3,
                    'subdomains': {
                        'backend': ['backend', 'server', 'api', 'database', 'web services'],
                        'frontend': ['frontend', 'ui', 'web development', 'javascript', 'react'],
                        'devops': ['devops', 'ci/cd', 'docker', 'kubernetes', 'cloud'],
                        'mobile': ['mobile', 'android', 'ios', 'app development']
                    }
                }
            }
            
            # Hardware Domain
            hardware_domains = {
                'pcb_design': {
                    'keywords': ['pcb', 'printed circuit board', 'altium', 'cadence allegro', 'eagle', 'kicad', 'layout'],
                    'score': 4,
                    'subdomains': {
                        'pcb_layout': ['pcb layout', 'board layout', 'routing', 'layer stack'],
                        'signal_integrity': ['signal integrity', 'si', 'crosstalk', 'impedance'],
                        'power_integrity': ['power integrity', 'pi', 'pdn', 'decoupling'],
                        'emi_emc': ['emi', 'emc', 'electromagnetic', 'compliance']
                    }
                },
                'test_engineering': {
                    'keywords': ['test engineer', 'validation', 'ate', 'test automation', 'characterization'],
                    'score': 4,
                    'subdomains': {
                        'ate': ['ate', 'automatic test equipment', 'test program', 'teradyne'],
                        'validation': ['validation', 'characterization', 'bench testing'],
                        'debug': ['debug', 'failure analysis', 'root cause', 'troubleshooting']
                    }
                }
            }
            
            # Combine all domains
            all_domains = {**vlsi_domains, **software_domains, **hardware_domains}
            
            # Experience level detection
            experience_keywords = {
                'entry': ['fresher', 'entry level', 'junior', 'graduate', 'recent graduate', 'new grad', '0 years', '1 year'],
                'mid': ['mid level', 'experienced', '2 years', '3 years', '4 years', '5 years', 'senior engineer'],
                'senior': ['senior', 'lead', 'principal', '6 years', '7 years', '8 years', '9 years', '10 years'],
                'expert': ['expert', 'architect', 'staff', 'principal', 'director', '10+ years', '15 years', '20 years']
            }
            
            # Analyze domain and subdomain
            best_domain = 'general'
            best_subdomain = 'unknown'
            max_domain_score = 0
            
            for domain_name, domain_info in all_domains.items():
                domain_score = 0
                found_subdomains = []
                
                # Check main domain keywords
                for keyword in domain_info['keywords']:
                    if keyword in all_text:
                        domain_score += domain_info['score']
                        keywords_found.append(keyword.title())
                
                # Check subdomain keywords
                for subdomain_name, subdomain_keywords in domain_info.get('subdomains', {}).items():
                    subdomain_score = 0
                    for keyword in subdomain_keywords:
                        if keyword in all_text:
                            subdomain_score += 2
                            keywords_found.append(f"{subdomain_name}: {keyword}")
                    
                    if subdomain_score > 0:
                        found_subdomains.append((subdomain_name, subdomain_score))
                        domain_score += subdomain_score
                
                # Update best domain if this scores higher
                if domain_score > max_domain_score:
                    max_domain_score = domain_score
                    best_domain = domain_name
                    
                    # Find best subdomain
                    if found_subdomains:
                        best_subdomain = max(found_subdomains, key=lambda x: x[1])[0]
                    else:
                        best_subdomain = 'general'
            
            score = max_domain_score
            domain = best_domain
            subdomain = best_subdomain
            
            # Determine experience level
            for exp_level, exp_keywords in experience_keywords.items():
                for keyword in exp_keywords:
                    if keyword in all_text:
                        experience_level = exp_level
                        break
                if experience_level != 'entry':
                    break
            
            # Additional scoring for attachments
            for attachment in attachments:
                filename = attachment.get('filename', '').lower()
                if any(ext in filename for ext in ['.pdf', '.doc', '.docx']):
                    score += 5
                if 'resume' in filename or 'cv' in filename:
                    score += 10
            
            # Determine final category based on domain and score
            if domain in vlsi_domains and score >= 20:
                category = f'high_priority_{domain}'
            elif domain in vlsi_domains and score >= 10:
                category = f'medium_priority_{domain}'
            elif domain in all_domains and score >= 8:
                category = f'medium_priority_{domain}'
            else:
                category = 'low_priority_general'
            
            return {
                'score': score,
                'category': category,
                'domain': domain,
                'subdomain': subdomain,
                'experience_level': experience_level,
                'keywords_found': keywords_found,
                'vlsi_relevant': domain in vlsi_domains and score >= 10
            }
            
        except Exception as e:
            self.add_log(f"❌ Resume analysis failed: {e}", 'error')
            return {
                'score': 0,
                'category': 'low_priority_general',
                'domain': 'general',
                'subdomain': 'unknown',
                'experience_level': 'entry',
                'keywords_found': [],
                'vlsi_relevant': False
            }

    def check_duplicate_resume(self, email_info: dict) -> dict:
        """Check for duplicate resumes based on sender email, content similarity, and attachments"""
        try:
            sender_email = email_info.get('from', '').lower()
            subject = email_info.get('subject', '').lower()
            attachments = email_info.get('attachments', [])
            
            # Extract sender email from "Name <email@domain.com>" format
            import re
            email_match = re.search(r'<([^>]+)>', sender_email)
            if email_match:
                sender_email = email_match.group(1)
            else:
                # Handle plain email format
                email_parts = sender_email.split()
                if email_parts:
                    sender_email = email_parts[-1]
            
            duplicate_info = {
                'is_duplicate': False,
                'duplicate_type': None,
                'confidence': 0,
                'previous_email_id': None,
                'reason': None
            }
            
            # Check against processed emails metadata stored in Drive
            if not self.drive_service:
                return duplicate_info
            
            try:
                # Search for existing metadata files
                folder_id = self.stats['drive_folders'].get('email_metadata')
                if not folder_id:
                    return duplicate_info
                
                # Get all metadata files
                results = self.drive_service.files().list(
                    q=f"parents in '{folder_id}' and name contains 'email_metadata'",
                    fields="files(id, name)"
                ).execute()
                
                for file_info in results.get('files', []):
                    try:
                        # Download and parse metadata file
                        file_content = self.drive_service.files().get_media(fileId=file_info['id']).execute()
                        metadata = json.loads(file_content.decode('utf-8'))
                        
                        prev_sender = metadata.get('from', '').lower()
                        prev_subject = metadata.get('subject', '').lower()
                        prev_attachments = metadata.get('attachments', [])
                        
                        # Extract previous sender email
                        prev_email_match = re.search(r'<([^>]+)>', prev_sender)
                        if prev_email_match:
                            prev_sender_email = prev_email_match.group(1)
                        else:
                            prev_sender_parts = prev_sender.split()
                            if prev_sender_parts:
                                prev_sender_email = prev_sender_parts[-1]
                            else:
                                prev_sender_email = prev_sender
                        
                        # Check for exact email match
                        if sender_email == prev_sender_email:
                            duplicate_info['is_duplicate'] = True
                            duplicate_info['duplicate_type'] = 'same_sender'
                            duplicate_info['confidence'] = 90
                            duplicate_info['previous_email_id'] = metadata.get('email_id')
                            duplicate_info['reason'] = f'Same sender email: {sender_email}'
                            
                            # Check for similar subjects
                            subject_similarity = self.calculate_text_similarity(subject, prev_subject)
                            if subject_similarity > 0.8:
                                duplicate_info['confidence'] = 95
                                duplicate_info['duplicate_type'] = 'same_sender_similar_subject'
                                duplicate_info['reason'] += f' with similar subject (similarity: {subject_similarity:.2f})'
                            
                            return duplicate_info
                        
                        # Check for similar attachments (same filename and size)
                        if attachments and prev_attachments:
                            attachment_similarity = self.compare_attachments(attachments, prev_attachments)
                            if attachment_similarity > 0.8:
                                duplicate_info['is_duplicate'] = True
                                duplicate_info['duplicate_type'] = 'similar_attachments'
                                duplicate_info['confidence'] = 85
                                duplicate_info['previous_email_id'] = metadata.get('email_id')
                                duplicate_info['reason'] = f'Similar attachments (similarity: {attachment_similarity:.2f})'
                                return duplicate_info
                        
                        # Check for very similar subjects (possible resubmission)
                        subject_similarity = self.calculate_text_similarity(subject, prev_subject)
                        if subject_similarity > 0.9:
                            duplicate_info['is_duplicate'] = True
                            duplicate_info['duplicate_type'] = 'similar_subject'
                            duplicate_info['confidence'] = 75
                            duplicate_info['previous_email_id'] = metadata.get('email_id')
                            duplicate_info['reason'] = f'Very similar subject (similarity: {subject_similarity:.2f})'
                            return duplicate_info
                        
                    except Exception as file_error:
                        self.add_log(f"❌ Error processing metadata file {file_info['name']}: {file_error}", 'warning')
                        continue
                
            except Exception as search_error:
                self.add_log(f"❌ Error searching for duplicates: {search_error}", 'warning')
            
            return duplicate_info
            
        except Exception as e:
            self.add_log(f"❌ Duplicate check failed: {e}", 'error')
            return {
                'is_duplicate': False,
                'duplicate_type': None,
                'confidence': 0,
                'previous_email_id': None,
                'reason': None
            }

    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity using simple word overlap"""
        try:
            if not text1 or not text2:
                return 0.0
            
            # Simple word-based similarity
            words1 = set(text1.lower().split())
            words2 = set(text2.lower().split())
            
            if not words1 or not words2:
                return 0.0
            
            intersection = words1.intersection(words2)
            union = words1.union(words2)
            
            return len(intersection) / len(union) if union else 0.0
            
        except Exception as e:
            self.add_log(f"❌ Text similarity calculation failed: {e}", 'warning')
            return 0.0

    def compare_attachments(self, attachments1: list, attachments2: list) -> float:
        """Compare two sets of attachments for similarity"""
        try:
            if not attachments1 or not attachments2:
                return 0.0
            
            # Create sets of (filename, size) tuples for comparison
            set1 = set()
            for att in attachments1:
                filename = att.get('filename', '').lower()
                size = att.get('size', 0)
                set1.add((filename, size))
            
            set2 = set()
            for att in attachments2:
                filename = att.get('filename', '').lower()
                size = att.get('size', 0)
                set2.add((filename, size))
            
            if not set1 or not set2:
                return 0.0
            
            intersection = set1.intersection(set2)
            union = set1.union(set2)
            
            return len(intersection) / len(union) if union else 0.0
            
        except Exception as e:
            self.add_log(f"❌ Attachment comparison failed: {e}", 'warning')
            return 0.0

    def setup_enhanced_drive_folders(self):
        """Setup enhanced Google Drive folder structure with domain-based organization"""
        try:
            if not self.drive_service:
                return {'success': False, 'error': 'Drive service not available'}
            
            self.add_log("📁 Setting up enhanced Google Drive folder structure", 'info')
            
            # Main folder
            main_folder_name = 'VLSI_Resume_Scanner_Enhanced'
            query = f"name='{main_folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            results = self.drive_service.files().list(q=query).execute()
            
            if results.get('files'):
                main_folder_id = results['files'][0]['id']
                self.add_log(f"✅ Found existing main folder: {main_folder_id}", 'info')
            else:
                main_folder_metadata = {
                    'name': main_folder_name,
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                main_folder = self.drive_service.files().create(body=main_folder_metadata).execute()
                main_folder_id = main_folder.get('id')
                self.add_log(f"✅ Created main folder: {main_folder_id}", 'info')
            
            self.stats['drive_folders']['main'] = main_folder_id
            
            # Domain-based folder structure
            domain_folders = {
                'VLSI_Digital_Design': ['RTL_Design', 'Verification', 'Synthesis', 'Timing_Analysis', 'DFT'],
                'VLSI_Analog_Design': ['RF_Design', 'Power_Management', 'Data_Converters', 'Analog_Mixed_Signal'],
                'VLSI_Physical_Design': ['Floorplanning', 'Routing', 'CTS', 'Sign_Off'],
                'VLSI_Memory_Design': ['SRAM', 'DRAM', 'Flash', 'Memory_Interface'],
                'VLSI_ASIC_Design': ['SoC_Design', 'Chip_Architecture', 'Silicon', 'Validation'],
                'VLSI_FPGA_Design': ['FPGA_Development', 'FPGA_Tools', 'Embedded_FPGA'],
                'Software_Embedded': ['Firmware', 'RTOS', 'Drivers', 'Protocols'],
                'Software_General': ['Backend', 'Frontend', 'DevOps', 'Mobile'],
                'Hardware_PCB': ['PCB_Layout', 'Signal_Integrity', 'Power_Integrity', 'EMI_EMC'],
                'Hardware_Test': ['ATE', 'Validation', 'Debug'],
                'Experience_Levels': ['Entry_Level', 'Mid_Level', 'Senior_Level', 'Expert_Level'],
                'Duplicates': ['Same_Sender', 'Similar_Attachments', 'Similar_Subject'],
                'Metadata': ['Email_Metadata', 'Duplicate_Reports', 'Statistics']
            }
            
            # Create domain folders and subfolders
            for domain_name, subfolders in domain_folders.items():
                # Create domain folder
                domain_query = f"name='{domain_name}' and parents in '{main_folder_id}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
                results = self.drive_service.files().list(q=domain_query).execute()
                
                if results.get('files'):
                    domain_folder_id = results['files'][0]['id']
                    self.add_log(f"✅ Found existing domain folder: {domain_name}", 'info')
                else:
                    domain_metadata = {
                        'name': domain_name,
                        'parents': [main_folder_id],
                        'mimeType': 'application/vnd.google-apps.folder'
                    }
                    domain_folder = self.drive_service.files().create(body=domain_metadata).execute()
                    domain_folder_id = domain_folder.get('id')
                    self.add_log(f"✅ Created domain folder: {domain_name}", 'info')
                
                self.stats['drive_folders'][domain_name.lower()] = domain_folder_id
                
                # Create subfolders
                for subfolder_name in subfolders:
                    subfolder_query = f"name='{subfolder_name}' and parents in '{domain_folder_id}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
                    results = self.drive_service.files().list(q=subfolder_query).execute()
                    
                    if not results.get('files'):
                        subfolder_metadata = {
                            'name': subfolder_name,
                            'parents': [domain_folder_id],
                            'mimeType': 'application/vnd.google-apps.folder'
                        }
                        subfolder = self.drive_service.files().create(body=subfolder_metadata).execute()
                        self.add_log(f"✅ Created subfolder: {subfolder_name}", 'info')
                    
                    self.stats['drive_folders'][f"{domain_name.lower()}_{subfolder_name.lower()}"] = subfolder.get('id') if not results.get('files') else results['files'][0]['id']
            
            self.add_log("✅ Enhanced Google Drive folder structure setup complete", 'info')
            return {'success': True, 'folders': self.stats['drive_folders']}
            
        except Exception as e:
            self.add_log(f"❌ Enhanced drive folder setup failed: {e}", 'error')
            return {'success': False, 'error': str(e)}

    def download_and_save_attachments(self, email_id: str, attachments: list, category: str) -> list:
        """Download email attachments and save to appropriate Drive folder"""
        try:
            if not self.gmail_service or not self.drive_service:
                return []
            
            saved_files = []
            folder_id = self.stats['drive_folders'].get('resume_attachments')
            
            if not folder_id:
                self.add_log("❌ Resume attachments folder not found", 'error')
                return []
            
            for attachment_info in attachments:
                try:
                    filename = attachment_info.get('filename', 'unknown_attachment')
                    attachment_id = attachment_info.get('attachment_id')
                    
                    if not attachment_id:
                        continue
                    
                    # Download attachment from Gmail
                    attachment = self.gmail_service.users().messages().attachments().get(
                        userId='me',
                        messageId=email_id,
                        id=attachment_id
                    ).execute()
                    
                    # Decode attachment data
                    file_data = base64.urlsafe_b64decode(attachment['data'])
                    
                    # Create file metadata for Drive
                    file_metadata = {
                        'name': f"{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}",
                        'parents': [folder_id]
                    }
                    
                    # Upload to Google Drive
                    media = MediaIoBaseUpload(
                        io.BytesIO(file_data),
                        mimetype=attachment_info.get('mime_type', 'application/octet-stream'),
                        resumable=True
                    )
                    
                    file = self.drive_service.files().create(
                        body=file_metadata,
                        media_body=media
                    ).execute()
                    
                    saved_files.append({
                        'filename': filename,
                        'drive_file_id': file.get('id'),
                        'size': len(file_data),
                        'category': category
                    })
                    
                    self.add_log(f"✅ Saved attachment: {filename} to Drive", 'info')
                    
                except Exception as attachment_error:
                    self.add_log(f"❌ Failed to save attachment {filename}: {attachment_error}", 'error')
                    continue
            
            return saved_files
            
        except Exception as e:
            self.add_log(f"❌ Attachment download failed: {e}", 'error')
            return []

    def save_email_metadata_to_drive(self, email_data: dict, category: str) -> bool:
        """Save email metadata as JSON to Google Drive"""
        try:
            if not self.drive_service:
                return False
            
            folder_id = self.stats['drive_folders'].get('email_metadata')
            if not folder_id:
                return False
            
            # Create metadata file
            metadata = {
                'email_id': email_data.get('id'),
                'from': email_data.get('from'),
                'subject': email_data.get('subject'),
                'date': email_data.get('date'),
                'category': category,
                'score': email_data.get('score', 0),
                'keywords_found': email_data.get('keywords_found', []),
                'processed_date': datetime.now().isoformat(),
                'attachments': email_data.get('saved_attachments', [])
            }
            
            # Convert to JSON
            json_data = json.dumps(metadata, indent=2)
            
            # Upload to Drive
            file_metadata = {
                'name': f"email_metadata_{email_data.get('id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                'parents': [folder_id]
            }
            
            media = MediaIoBaseUpload(
                io.BytesIO(json_data.encode('utf-8')),
                mimetype='application/json',
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media
            ).execute()
            
            self.add_log(f"✅ Saved email metadata: {file.get('id')}", 'info')
            return True
            
        except Exception as e:
            self.add_log(f"❌ Failed to save email metadata: {e}", 'error')
            return False

    def scan_gmail_for_resumes(self, max_emails=100, full_scan=False):
        """Scan Gmail for resumes and categorize them in Google Drive"""
        try:
            if not self.gmail_service:
                return {'success': False, 'error': 'Gmail service not authenticated'}
            
            # FOR TESTING: Limit max_emails to reasonable number
            if max_emails > 500:
                max_emails = 500  # Safety limit for testing
                self.add_log(f"⚠️ Limited scan to {max_emails} emails for safety", 'warning')
            
            scan_type = "FULL" if full_scan else "INCREMENTAL"
            self.add_log(f"📧 Starting {scan_type} Gmail scan (LIMITED to {max_emails} emails for testing)", 'info')
            
            # Search queries for different types of resumes
            resume_queries = [
                'subject:(resume OR CV OR "curriculum vitae")',
                'has:attachment filename:(pdf OR doc OR docx)',
                'subject:(application OR applying OR "job application")',
                '"attached resume" OR "my resume" OR "my CV"',
                'subject:(vlsi OR verilog OR vhdl OR asic OR fpga OR semiconductor)',
                'body:(vlsi OR semiconductor OR "chip design" OR "digital design")'
            ]
            
            if not full_scan:
                # For incremental scan, only get emails newer than last scan
                if self.stats.get('last_scan_time'):
                    last_scan = datetime.fromisoformat(self.stats['last_scan_time'].replace('Z', '+00:00'))
                    cutoff_date = last_scan.strftime('%Y/%m/%d')
                    resume_queries = [f"({query}) after:{cutoff_date}" for query in resume_queries]
            
            all_emails = []
            processed_resumes = []
            
            # Calculate emails per query to stay within limit
            emails_per_query = max(1, max_emails // len(resume_queries))
            
            for query in resume_queries:
                try:
                    # Search Gmail with the query - LIMITED for testing
                    results = self.gmail_service.users().messages().list(
                        userId='me',
                        q=query,
                        maxResults=emails_per_query  # Limited per query
                    ).execute()
                    
                    messages = results.get('messages', [])
                    self.add_log(f"🔍 Found {len(messages)} emails for query: {query[:40]}... (limited to {emails_per_query})", 'info')
                    
                    for message in messages:
                        # TESTING LIMIT: Stop if we've processed enough
                        if len(all_emails) >= max_emails:
                            self.add_log(f"📊 Reached testing limit of {max_emails} emails", 'info')
                            break
                        
                        # Skip if already processed
                        if message['id'] in self.stats['processed_email_ids']:
                            continue
                            
                        try:
                            # Get full email details
                            email_data = self.gmail_service.users().messages().get(
                                userId='me',
                                id=message['id'],
                                format='full'
                            ).execute()
                            
                            # Extract headers
                            headers = email_data['payload'].get('headers', [])
                            email_info = {
                                'id': message['id'],
                                'from': next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown'),
                                'subject': next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject'),
                                'date': next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown'),
                                'attachments': [],
                                'body_preview': ''
                            }
                            
                            # Extract body preview
                            body_text = self.extract_email_body(email_data['payload'])
                            email_info['body_preview'] = body_text[:500] if body_text else ''
                            
                                email_info['saved_attachments'] = saved_attachments
                                
                                # Save email metadata with enhanced information
                                self.save_enhanced_email_metadata(email_info, analysis, target_folder)
                                
                                processed_resumes.append(email_info)
                                self.stats['processed_email_ids'].add(message['id'])
                                
                                self.add_log(f"📄 Processed resume: {email_info['subject'][:50]} | Domain: {analysis['domain']} | Subdomain: {analysis['subdomain']} | Experience: {analysis['experience_level']} | Score: {analysis['score']}", 'info')
                            
                        except Exception as email_error:
                            self.add_log(f"❌ Error processing email {message['id']}: {email_error}", 'warning')
                            continue
                            
                except Exception as query_error:
                    self.add_log(f"❌ Error with query '{query}': {query_error}", 'warning')
                    continue
            
            # Generate summary statistics
            domain_stats = self.generate_domain_statistics(processed_resumes)
            experience_stats = self.generate_experience_statistics(processed_resumes)
            
            # Update stats
            self.stats['total_emails'] = len(all_emails)
            self.stats['resumes_found'] = len(processed_resumes)
            self.stats['last_scan_time'] = datetime.now().isoformat()
            
            if full_scan:
                self.stats['last_full_scan'] = datetime.now().isoformat()
            
            self.add_log(f"✅ {scan_type} scan completed: {len(all_emails)} emails, {len(processed_resumes)} resumes processed", 'info')
            
            return {
                'success': True,
                'emails_scanned': len(all_emails),
                'resumes_found': len(processed_resumes),
                'resume_details': processed_resumes[:10],  # Return top 10 for display
                'scan_method': 'enhanced_gmail_api_with_domain_categorization',
                'scan_type': scan_type,
                'domain_statistics': domain_stats,
                'experience_statistics': experience_stats,
                'categories': self.get_enhanced_category_counts(processed_resumes)
            }
            
        except Exception as e:
            self.add_log(f"❌ Gmail scan failed: {e}", 'error')
            return {'success': False, 'error': str(e)}

    def get_target_folder(self, analysis: dict) -> str:
        """Determine target folder based on domain, subdomain, and experience"""
        try:
            domain = analysis.get('domain', 'general')
            subdomain = analysis.get('subdomain', 'unknown')
            experience = analysis.get('experience_level', 'entry')
            
            # Map domain to folder structure
            domain_folder_mapping = {
                'digital_design': 'vlsi_digital_design',
                'analog_design': 'vlsi_analog_design',
                'physical_design': 'vlsi_physical_design',
                'memory_design': 'vlsi_memory_design',
                'asic_design': 'vlsi_asic_design',
                'fpga_design': 'vlsi_fpga_design',
                'embedded_software': 'software_embedded',
                'software_engineering': 'software_general',
                'pcb_design': 'hardware_pcb',
                'test_engineering': 'hardware_test'
            }
            
            # Get base folder
            base_folder = domain_folder_mapping.get(domain, 'metadata')
            
            # Try to get specific subdomain folder
            if subdomain != 'unknown':
                subdomain_folder_key = f"{base_folder}_{subdomain}"
                if subdomain_folder_key in self.stats['drive_folders']:
                    return subdomain_folder_key
            
            # Fallback to domain folder
            return base_folder
            
        except Exception as e:
            self.add_log(f"❌ Error determining target folder: {e}", 'warning')
            return 'metadata'

    def download_and_save_attachments(self, email_id: str, attachments: list, target_folder: str, analysis: dict) -> list:
        """Enhanced attachment download with domain-based organization"""
        try:
            if not self.gmail_service or not self.drive_service:
                return []
            
            saved_files = []
            folder_id = self.stats['drive_folders'].get(target_folder)
            
            if not folder_id:
                # Fallback to main folder
                folder_id = self.stats['drive_folders'].get('main')
                if not folder_id:
                    self.add_log("❌ No suitable folder found for attachments", 'error')
                    return []
            
            for attachment_info in attachments:
                try:
                    filename = attachment_info.get('filename', 'unknown_attachment')
                    attachment_id = attachment_info.get('attachment_id')
                    
                    if not attachment_id:
                        continue
                    
                    # Download attachment from Gmail
                    attachment = self.gmail_service.users().messages().attachments().get(
                        userId='me',
                        messageId=email_id,
                        id=attachment_id
                    ).execute()
                    
                    # Decode attachment data
                    file_data = base64.urlsafe_b64decode(attachment['data'])
                    
                    # Create enhanced filename with metadata
                    domain = analysis.get('domain', 'unknown')
                    subdomain = analysis.get('subdomain', 'unknown')
                    experience = analysis.get('experience_level', 'entry')
                    score = analysis.get('score', 0)
                    
                    enhanced_filename = f"{domain}_{subdomain}_{experience}_score{score}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                    
                    # Create file metadata for Drive
                    file_metadata = {
                        'name': enhanced_filename,
                        'parents': [folder_id],
                        'description': f"Resume attachment - Domain: {domain}, Subdomain: {subdomain}, Experience: {experience}, Score: {score}"
                    }
                    
                    # Upload to Google Drive
                    media = MediaIoBaseUpload(
                        io.BytesIO(file_data),
                        mimetype=attachment_info.get('mime_type', 'application/octet-stream'),
                        resumable=True
                    )
                    
                    file = self.drive_service.files().create(
                        body=file_metadata,
                        media_body=media
                    ).execute()
                    
                    saved_files.append({
                        'filename': filename,
                        'enhanced_filename': enhanced_filename,
                        'drive_file_id': file.get('id'),
                        'size': len(file_data),
                        'domain': domain,
                        'subdomain': subdomain,
                        'experience_level': experience,
                        'target_folder': target_folder
                    })
                    
                    self.add_log(f"✅ Saved attachment: {filename} to {target_folder}", 'info')
                    
                except Exception as attachment_error:
                    self.add_log(f"❌ Failed to save attachment {filename}: {attachment_error}", 'error')
                    continue
            
            return saved_files
            
        except Exception as e:
            self.add_log(f"❌ Enhanced attachment download failed: {e}", 'error')
            return []

    def save_enhanced_email_metadata(self, email_data: dict, analysis: dict, target_folder: str) -> bool:
        """Save enhanced email metadata with domain categorization"""
        try:
            if not self.drive_service:
                return False
            
            folder_id = self.stats['drive_folders'].get('metadata')
            if not folder_id:
                return False
            
            # Create enhanced metadata
            metadata = {
                'email_id': email_data.get('id'),
                'from': email_data.get('from'),
                'subject': email_data.get('subject'),
                'date': email_data.get('date'),
                'domain': analysis.get('domain'),
                'subdomain': analysis.get('subdomain'),
                'experience_level': analysis.get('experience_level'),
                'score': analysis.get('score', 0),
                'keywords_found': analysis.get('keywords_found', []),
                'target_folder': target_folder,
                'processed_date': datetime.now().isoformat(),
                'attachments': email_data.get('saved_attachments', []),
                'duplicate_info': {
                    'is_duplicate': email_data.get('is_duplicate', False),
                    'duplicate_type': email_data.get('duplicate_type'),
                    'confidence': email_data.get('confidence', 0)
                },
                'body_preview': email_data.get('body_preview', '')[:200]  # First 200 chars
            }
            
            # Convert to JSON
            json_data = json.dumps(metadata, indent=2)
            
            # Create enhanced filename
            domain = analysis.get('domain', 'unknown')
            subdomain = analysis.get('subdomain', 'unknown')
            experience = analysis.get('experience_level', 'entry')
            
            filename = f"metadata_{domain}_{subdomain}_{experience}_{email_data.get('id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Upload to Drive
            file_metadata = {
                'name': filename,
                'parents': [folder_id],
                'description': f"Enhanced email metadata - Domain: {domain}, Subdomain: {subdomain}, Experience: {experience}"
            }
            
            media = MediaIoBaseUpload(
                io.BytesIO(json_data.encode('utf-8')),
                mimetype='application/json',
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media
            ).execute()
            
            self.add_log(f"✅ Saved enhanced email metadata: {file.get('id')}", 'info')
            return True
            
        except Exception as e:
            self.add_log(f"❌ Failed to save enhanced email metadata: {e}", 'error')
            return False

    def save_duplicate_report(self, email_data: dict, duplicate_info: dict) -> bool:
        """Save duplicate detection report"""
        try:
            if not self.drive_service:
                return False
            
            folder_id = self.stats['drive_folders'].get('duplicates')
            if not folder_id:
                return False
            
            # Create duplicate report
            duplicate_report = {
                'detected_email': {
                    'id': email_data.get('id'),
                    'from': email_data.get('from'),
                    'subject': email_data.get('subject'),
                    'date': email_data.get('date')
                },
                'duplicate_info': duplicate_info,
                'detection_date': datetime.now().isoformat(),
                'action_taken': 'skipped_processing'
            }
            
            # Convert to JSON
            json_data = json.dumps(duplicate_report, indent=2)
            
            # Create filename
            filename = f"duplicate_report_{duplicate_info['duplicate_type']}_{email_data.get('id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Upload to Drive
            file_metadata = {
                'name': filename,
                'parents': [folder_id],
                'description': f"Duplicate detection report - Type: {duplicate_info['duplicate_type']}, Confidence: {duplicate_info['confidence']}%"
            }
            
            media = MediaIoBaseUpload(
                io.BytesIO(json_data.encode('utf-8')),
                mimetype='application/json',
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media
            ).execute()
            
            self.add_log(f"✅ Saved duplicate report: {file.get('id')}", 'info')
            return True
            
        except Exception as e:
            self.add_log(f"❌ Failed to save duplicate report: {e}", 'error')
            return False

    def generate_domain_statistics(self, resumes: list) -> dict:
        """Generate statistics by domain and subdomain"""
        try:
            stats = {
                'by_domain': {},
                'by_subdomain': {},
                'by_experience': {},
                'top_keywords': {}
            }
            
            # Count by domain
            for resume in resumes:
                domain = resume.get('domain', 'unknown')
                subdomain = resume.get('subdomain', 'unknown')
                experience = resume.get('experience_level', 'entry')
                keywords = resume.get('keywords_found', [])
                
                # Domain stats
                if domain in stats['by_domain']:
                    stats['by_domain'][domain] += 1
                else:
                    stats['by_domain'][domain] = 1
                
                # Subdomain stats
                subdomain_key = f"{domain}_{subdomain}"
                if subdomain_key in stats['by_subdomain']:
                    stats['by_subdomain'][subdomain_key] += 1
                else:
                    stats['by_subdomain'][subdomain_key] = 1
                
                # Experience stats
                if experience in stats['by_experience']:
                    stats['by_experience'][experience] += 1
                else:
                    stats['by_experience'][experience] = 1
                
                # Keyword stats
                for keyword in keywords:
                    if keyword in stats['top_keywords']:
                        stats['top_keywords'][keyword] += 1
                    else:
                        stats['top_keywords'][keyword] = 1
            
            # Sort top keywords
            stats['top_keywords'] = dict(sorted(stats['top_keywords'].items(), key=lambda x: x[1], reverse=True)[:20])
            
            return stats
            
        except Exception as e:
            self.add_log(f"❌ Error generating domain statistics: {e}", 'warning')
            return {}

    def generate_experience_statistics(self, resumes: list) -> dict:
        """Generate experience level statistics"""
        try:
            exp_stats = {
                'entry': {'count': 0, 'domains': {}},
                'mid': {'count': 0, 'domains': {}},
                'senior': {'count': 0, 'domains': {}},
                'expert': {'count': 0, 'domains': {}}
            }
            
            for resume in resumes:
                experience = resume.get('experience_level', 'entry')
                domain = resume.get('domain', 'unknown')
                
                if experience in exp_stats:
                    exp_stats[experience]['count'] += 1
                    
                    if domain in exp_stats[experience]['domains']:
                        exp_stats[experience]['domains'][domain] += 1
                    else:
                        exp_stats[experience]['domains'][domain] = 1
            
            return exp_stats
            
        except Exception as e:
            self.add_log(f"❌ Error generating experience statistics: {e}", 'warning')
            return {}

    def get_enhanced_category_counts(self, resumes: list) -> dict:
        """Get enhanced category counts with domain breakdown"""
        try:
            counts = {
                'total': len(resumes),
                'by_domain': {},
                'by_experience': {},
                'by_score_range': {
                    'high_score': 0,  # 20+ points
                    'medium_score': 0,  # 10-19 points
                    'low_score': 0   # <10 points
                }
            }
            
            for resume in resumes:
                domain = resume.get('domain', 'unknown')
                experience = resume.get('experience_level', 'entry')
                score = resume.get('score', 0)
                
                # Domain counts
                if domain in counts['by_domain']:
                    counts['by_domain'][domain] += 1
                else:
                    counts['by_domain'][domain] = 1
                
                # Experience counts
                if experience in counts['by_experience']:
                    counts['by_experience'][experience] += 1
                else:
                    counts['by_experience'][experience] = 1
                
                # Score range counts
                if score >= 20:
                    counts['by_score_range']['high_score'] += 1
                elif score >= 10:
                    counts['by_score_range']['medium_score'] += 1
                else:
                    counts['by_score_range']['low_score'] += 1
            
            return counts
            
        except Exception as e:
            self.add_log(f"❌ Error calculating enhanced category counts: {e}", 'warning')
            return {}

    def setup_drive_folders(self):
        """Wrapper method that calls enhanced folder setup"""
        return self.setup_enhanced_drive_folders() = saved_attachments
                                
                                # Save email metadata
                                self.save_email_metadata_to_drive(email_info, analysis['category'])
                                
                                processed_resumes.append(email_info)
                                self.stats['processed_email_ids'].add(message['id'])
                                
                                self.add_log(f"📄 Processed resume: {email_info['subject'][:50]} (Category: {analysis['category']}, Score: {analysis['score']})", 'info')
                            
                        except Exception as email_error:
                            self.add_log(f"❌ Error processing email {message['id']}: {email_error}", 'warning')
                            continue
                            
                except Exception as query_error:
                    self.add_log(f"❌ Error with query '{query}': {query_error}", 'warning')
                    continue
            
            # Update stats
            self.stats['total_emails'] = len(all_emails)
            self.stats['resumes_found'] = len(processed_resumes)
            self.stats['last_scan_time'] = datetime.now().isoformat()
            
            if full_scan:
                self.stats['last_full_scan'] = datetime.now().isoformat()
            
            self.add_log(f"✅ {scan_type} scan completed: {len(all_emails)} emails, {len(processed_resumes)} resumes processed", 'info')
            
            return {
                'success': True,
                'emails_scanned': len(all_emails),
                'resumes_found': len(processed_resumes),
                'resume_details': processed_resumes[:10],  # Return top 10 for display
                'scan_method': 'real_gmail_api_with_drive_sync',
                'scan_type': scan_type,
                'categories': self.get_category_counts(processed_resumes)
            }
            
        except Exception as e:
            self.add_log(f"❌ Gmail scan failed: {e}", 'error')
            return {'success': False, 'error': str(e)}

    def extract_email_body(self, payload):
        """Extract text content from email payload"""
        try:
            body_text = ""
            
            if payload.get('body', {}).get('data'):
                body_text = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
            elif payload.get('parts'):
                for part in payload['parts']:
                    if part.get('mimeType') == 'text/plain' and part.get('body', {}).get('data'):
                        body_text += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                    elif part.get('parts'):
                        body_text += self.extract_email_body(part)
            
            return body_text
            
        except Exception as e:
            self.add_log(f"❌ Error extracting email body: {e}", 'warning')
            return ""

    def extract_attachments(self, payload, message_id):
        """Extract attachment information from email payload"""
        try:
            attachments = []
            
            def process_parts(parts):
                for part in parts:
                    if part.get('filename') and part['filename']:
                        attachment_info = {
                            'filename': part['filename'],
                            'mime_type': part.get('mimeType', 'unknown'),
                            'size': part['body'].get('size', 0),
                            'attachment_id': part['body'].get('attachmentId')
                        }
                        
                        # Only include resume-like attachments
                        filename_lower = part['filename'].lower()
                        if any(ext in filename_lower for ext in ['.pdf', '.doc', '.docx', '.txt']):
                            attachments.append(attachment_info)
                    
                    if part.get('parts'):
                        process_parts(part['parts'])
            
            if payload.get('parts'):
                process_parts(payload['parts'])
            
            return attachments
            
        except Exception as e:
            self.add_log(f"❌ Error extracting attachments: {e}", 'warning')
            return []

    def get_category_counts(self, resumes):
        """Get count of resumes by category"""
        try:
            counts = {
                'high_priority_vlsi': 0,
                'medium_priority_technical': 0,
                'low_priority_general': 0
            }
            
            for resume in resumes:
                category = resume.get('category', 'low_priority_general')
                if category in counts:
                    counts[category] += 1
            
            return counts
            
        except Exception as e:
            self.add_log(f"❌ Error calculating category counts: {e}", 'warning')
            return {}

    def start_auto_sync(self):
        """Start automatic scanning every 2 hours"""
        try:
            if self.stats['auto_sync_active']:
                return {'success': False, 'error': 'Auto-sync already running'}
            
            if not self.gmail_service or not self.drive_service:
                return {'success': False, 'error': 'Google services not authenticated'}
            
            self.stop_auto_sync = False
            self.stats['auto_sync_active'] = True
            
            # Start background thread
            self.auto_sync_thread = threading.Thread(target=self._auto_sync_worker, daemon=True)
            self.auto_sync_thread.start()
            
            self.add_log("🔄 Auto-sync started - will scan every 2 hours", 'info')
            return {'success': True, 'message': 'Auto-sync started successfully'}
            
        except Exception as e:
            self.add_log(f"❌ Failed to start auto-sync: {e}", 'error')
            return {'success': False, 'error': str(e)}

    def stop_auto_sync_process(self):
        """Stop automatic scanning"""
        try:
            self.stop_auto_sync = True
            self.stats['auto_sync_active'] = False
            
            self.add_log("⏹️ Auto-sync stopped", 'info')
            return {'success': True, 'message': 'Auto-sync stopped successfully'}
            
        except Exception as e:
            self.add_log(f"❌ Failed to stop auto-sync: {e}", 'error')
            return {'success': False, 'error': str(e)}

    def _auto_sync_worker(self):
        """Background worker for auto-sync"""
        try:
            # Perform initial full scan if never done - LIMITED for testing
            if not self.stats.get('last_full_scan'):
                self.add_log("🔄 Performing initial full scan (LIMITED to 100 emails for testing)", 'info')
                self.scan_gmail_for_resumes(max_emails=100, full_scan=True)  # Limited for testing
            
            # Then run incremental scans every 2 hours
            while not self.stop_auto_sync:
                try:
                    # Wait for 2 hours (7200 seconds)
                    for _ in range(720):  # Check every 10 seconds for stop signal
                        if self.stop_auto_sync:
                            break
                        time.sleep(10)
                    
                    if not self.stop_auto_sync:
                        self.add_log("🔄 Running scheduled incremental scan (LIMITED to 50 emails for testing)", 'info')
                        self.scan_gmail_for_resumes(max_emails=50, full_scan=False)  # Limited for testing
                    
                except Exception as scan_error:
                    self.add_log(f"❌ Auto-sync scan error: {scan_error}", 'error')
                    time.sleep(300)  # Wait 5 minutes before retrying
            
        except Exception as e:
            self.add_log(f"❌ Auto-sync worker failed: {e}", 'error')
        finally:
            self.stats['auto_sync_active'] = False

# Initialize scanner
scanner = VLSIResumeScanner()

# RAILWAY FIX 4: Add health check and startup optimization (Flask 2.3+ compatible)
def initialize_app():
    """Initialize app - this runs on startup"""
    app.logger.info("🚀 VLSI Resume Scanner starting up...")
    app.logger.info(f"📊 Google APIs available: {GOOGLE_APIS_AVAILABLE}")
    app.logger.info(f"🔧 Environment: Railway Cloud")

# Call initialization immediately
with app.app_context():
    initialize_app()

@app.route('/health')
def health_check():
    """Railway health check endpoint - CRITICAL for Railway"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'google_apis': GOOGLE_APIS_AVAILABLE,
        'pdf_processing': PDF_PROCESSING_AVAILABLE,
        'auto_sync_active': scanner.stats['auto_sync_active'],
        'message': 'VLSI Resume Scanner is running successfully on Railway'
    }), 200

# RAILWAY FIX 5: Add startup route for faster initial response
@app.route('/startup')
def startup_check():
    """Quick startup check - helps Railway detect successful deployment"""
    return jsonify({
        'status': 'ready',
        'timestamp': datetime.now().isoformat(),
        'message': 'Application ready to serve requests'
    }), 200

@app.route('/')
def index():
    """Main dashboard - RAILWAY OPTIMIZED with Auto-Sync Features"""
    try:
        # Quick check for Railway environment
        is_railway = os.environ.get('RAILWAY_ENVIRONMENT') is not None
        
        # Log the request for Railway monitoring
        app.logger.info(f"📊 Dashboard accessed - Railway: {is_railway}")
        
        # Check credentials quickly
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
            <title>🔬 VLSI Resume Scanner - Auto-Sync</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh; padding: 20px; color: #333;
                }
                .container { 
                    max-width: 1400px; margin: 0 auto; 
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
                .status h3 { color: #2e7d32; margin-bottom: 10px; }
                .status p { color: #388e3c; }
                .auth-section {
                    background: #f8f9fa; border-radius: 10px; 
                    padding: 20px; margin-bottom: 30px; text-align: center;
                }
                .setup-section {
                    background: #e3f2fd; border: 2px solid #2196f3;
                    border-radius: 10px; padding: 30px; margin: 20px 0;
                    text-align: center;
                }
                .input-group {
                    display: flex; gap: 10px; margin-bottom: 20px;
                    justify-content: center; align-items: center; flex-wrap: wrap;
                }
                .input-group input {
                    padding: 12px; border: 1px solid #ddd;
                    border-radius: 5px; font-size: 1em; min-width: 250px;
                }
                .input-group button, .btn {
                    padding: 12px 24px; background: #4a90e2; color: white;
                    border: none; border-radius: 5px; cursor: pointer;
                    font-size: 1em; margin: 5px;
                }
                .input-group button:hover, .btn:hover { background: #357abd; }
                .btn-success { background: #28a745; }
                .btn-success:hover { background: #218838; }
                .btn-warning { background: #ffc107; color: #212529; }
                .btn-warning:hover { background: #e0a800; }
                .btn-danger { background: #dc3545; }
                .btn-danger:hover { background: #c82333; }
                .main-content, .setup-content { display: none; }
                .dashboard-grid {
                    display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px; margin-top: 30px;
                }
                .card {
                    background: #f8f9fa; border-radius: 10px; padding: 20px;
                    border-left: 4px solid #4a90e2; min-height: 180px;
                }
                .card h4 { color: #4a90e2; margin-bottom: 15px; }
                .card p { margin-bottom: 10px; line-height: 1.5; }
                .logs-container {
                    max-height: 250px; overflow-y: auto; 
                    background: #f1f1f1; padding: 10px; border-radius: 5px;
                    font-family: monospace; font-size: 0.9em;
                }
                .log-entry { margin-bottom: 5px; }
                .log-info { color: #0066cc; }
                .log-warning { color: #ff8800; }
                .log-error { color: #cc0000; }
                .oauth-section {
                    background: #fff3cd; border: 1px solid #ffeaa7;
                    border-radius: 10px; padding: 20px; margin: 20px 0;
                }
                .oauth-url {
                    background: #f8f9fa; padding: 10px; border-radius: 5px;
                    word-break: break-all; margin: 10px 0; font-size: 0.9em;
                }
                .hidden { display: none; }
                .form-group { margin-bottom: 15px; }
                .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
                .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
                .form-group small { color: #666; font-size: 0.9em; }
                .railway-badge {
                    background: #0070f3; color: white; padding: 5px 10px;
                    border-radius: 15px; font-size: 0.9em; margin-left: 10px;
                }
                .auto-sync-indicator {
                    display: inline-block; width: 10px; height: 10px;
                    border-radius: 50%; margin-right: 5px;
                }
                .sync-active { background-color: #28a745; }
                .sync-inactive { background-color: #dc3545; }
                .category-stats {
                    display: grid; grid-template-columns: repeat(3, 1fr);
                    gap: 10px; margin-top: 15px;
                }
                .category-item {
                    background: white; padding: 10px; border-radius: 5px;
                    text-align: center; border: 1px solid #ddd;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔬 VLSI Resume Scanner</h1>
                    <p>AI-Powered Resume Analysis with Auto-Sync & Google Drive Integration<span class="railway-badge">⚡ Railway</span></p>
                </div>
                
                <div class="content">
                    <div class="status">
                        <h3>✅ Railway Deployment Successful!</h3>
                        <p>Application with auto-sync capabilities is running and ready for Google API integration.</p>
                    </div>

                    <div id="auth-section" class="auth-section">
                        <h3>🔐 Admin Authentication</h3>
                        <div class="input-group">
                            <input type="password" id="admin-password" placeholder="Enter admin password">
                            <button onclick="authenticate()">🔑 Login</button>
                        </div>
                        <p>Enter admin password to access the VLSI Resume Scanner dashboard</p>
                    </div>

                    <div id="setup-content" class="setup-content">
                        <div class="setup-section">
                            <h2>🛠️ Google API Setup</h2>
                            <p>Enter your Google API credentials to get started</p>
                            
                            <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: left;">
                                <h4>🔑 Enter Google API Credentials</h4>
                                
                                <div class="form-group">
                                    <label for="client-id">Google Client ID</label>
                                    <input type="text" id="client-id" placeholder="123456789-abc...googleusercontent.com">
                                    <small>From Google Cloud Console → APIs & Services → Credentials</small>
                                </div>

                                <div class="form-group">
                                    <label for="client-secret">Google Client Secret</label>
                                    <input type="text" id="client-secret" placeholder="GOCSPX-abc123...">
                                    <small>Found next to the Client ID in Google Cloud Console</small>
                                </div>

                                <div class="form-group">
                                    <label for="project-id">Google Project ID</label>
                                    <input type="text" id="project-id" placeholder="vlsi-scanner-123456">
                                    <small>Found in Google Cloud Console project selector</small>
                                </div>

                                <div class="input-group">
                                    <button class="btn btn-success" onclick="saveCredentials()">💾 Save Credentials</button>
                                    <button class="btn" onclick="showMainDashboard()">⏭️ Skip for Now</button>
                                </div>
                            </div>
                            
                            <p><small>💡 <strong>Need help?</strong> Visit <a href="https://console.cloud.google.com/" target="_blank">Google Cloud Console</a> to create OAuth credentials</small></p>
                        </div>
                    </div>

                    <div id="main-content" class="main-content">
                        <h2>🎛️ VLSI Resume Scanner Dashboard</h2>
                        <p>Welcome to the admin panel. Configure Google API integration to start scanning and auto-syncing resumes.</p>
                        
                        <div class="dashboard-grid">
                            <div class="card">
                                <h4>📊 System Status</h4>
                                <div id="system-status">
                                    <p>Loading system status...</p>
                                </div>
                                <button class="btn" onclick="refreshStatus()">🔄 Refresh Status</button>
                                ''' + ('<!-- Credentials configured via Railway -->' if has_credentials else '<button class="btn" onclick="showSetupSection()">🛠️ Setup Credentials</button>') + '''
                            </div>
                            
                            <div class="card">
                                <h4>🔧 Google API Setup</h4>
                                <p>Configure Gmail, Drive, and Sheets integration</p>
                                <button class="btn btn-success" onclick="setupGoogleAuth()" id="setup-btn">
                                    🚀 Start Google Authentication
                                </button>
                                <div id="oauth-section" class="oauth-section hidden">
                                    <h5>📋 OAuth Authorization Required</h5>
                                    <p>1. Click the link below to authorize the application:</p>
                                    <div id="auth-url" class="oauth-url"></div>
                                    <p>2. Copy the authorization code and paste it here:</p>
                                    <div class="input-group">
                                        <input type="text" id="auth-code" placeholder="Paste authorization code here">
                                        <button onclick="completeAuth()">✅ Complete Authentication</button>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="card">
                                <h4>📧 Resume Scanning</h4>
                                <p>Scan Gmail for resumes and organize them in Google Drive</p>
                                <div class="input-group">
                                    <button class="btn" onclick="startFullScan()" id="full-scan-btn" disabled>
                                        📊 Full Gmail Scan
                                    </button>
                                    <button class="btn" onclick="startIncrementalScan()" id="incremental-scan-btn" disabled>
                                        🔄 Incremental Scan
                                    </button>
                                </div>
                                <div id="scan-results"></div>
                                <div id="category-stats" class="category-stats hidden">
                                    <div class="category-item">
                                        <strong>High Score (20+)</strong><br>
                                        <span id="high-score-count">0</span> Resumes
                                    </div>
                                    <div class="category-item">
                                        <strong>Medium Score (10-19)</strong><br>
                                        <span id="medium-score-count">0</span> Resumes
                                    </div>
                                    <div class="category-item">
                                        <strong>Low Score (<10)</strong><br>
                                        <span id="low-score-count">0</span> Resumes
                                    </div>
                                </div>
                                <div id="domain-stats" class="category-stats hidden">
                                    <div class="category-item">
                                        <strong>VLSI Domains</strong><br>
                                        <span id="vlsi-domain-count">0</span> Resumes
                                    </div>
                                    <div class="category-item">
                                        <strong>Software Domains</strong><br>
                                        <span id="software-domain-count">0</span> Resumes
                                    </div>
                                    <div class="category-item">
                                        <strong>Hardware Domains</strong><br>
                                        <span id="hardware-domain-count">0</span> Resumes
                                    </div>
                                </div>
                                <div id="experience-stats" class="category-stats hidden">
                                    <div class="category-item">
                                        <strong>Entry Level</strong><br>
                                        <span id="entry-exp-count">0</span> Resumes
                                    </div>
                                    <div class="category-item">
                                        <strong>Mid Level</strong><br>
                                        <span id="mid-exp-count">0</span> Resumes
                                    </div>
                                    <div class="category-item">
                                        <strong>Senior Level</strong><br>
                                        <span id="senior-exp-count">0</span> Resumes
                                    </div>
                                </div>
                            </div>
                            
                            <div class="card">
                                <h4>🔄 Auto-Sync Control</h4>
                                <p>Automatic scanning every 2 hours with Google Drive sync</p>
                                <div id="auto-sync-status">
                                    <p><span class="auto-sync-indicator sync-inactive"></span>Auto-sync inactive</p>
                                </div>
                                <div class="input-group">
                                    <button class="btn btn-success" onclick="startAutoSync()" id="start-auto-sync-btn" disabled>
                                        ▶️ Start Auto-Sync
                                    </button>
                                    <button class="btn btn-danger" onclick="stopAutoSync()" id="stop-auto-sync-btn" disabled>
                                        ⏹️ Stop Auto-Sync
                                    </button>
                                </div>
                            </div>
                            
                            <div class="card">
                                <h4>📋 Activity Logs</h4>
                                <div id="logs-container" class="logs-container">
                                    <p>Logs will appear here...</p>
                                </div>
                                <button class="btn btn-warning" onclick="clearLogs()">🗑️ Clear Logs</button>
                            </div>
                            
                            <div class="card">
                                <h4>📁 Google Drive Integration</h4>
                                <p>Resume organization and storage status</p>
                                <div id="drive-status">
                                    <p>Drive integration status will appear here...</p>
                                </div>
                                <button class="btn" onclick="setupDriveFolders()">📁 Setup Drive Folders</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <script>
            function showSetupSection() {
                document.getElementById('main-content').style.display = 'none';
                document.getElementById('setup-content').style.display = 'block';
            }

            function showMainDashboard() {
                document.getElementById('setup-content').style.display = 'none';
                document.getElementById('main-content').style.display = 'block';
                refreshStatus();
            }

            function saveCredentials() {
                const clientId = document.getElementById('client-id').value;
                const clientSecret = document.getElementById('client-secret').value;
                const projectId = document.getElementById('project-id').value;
                
                if (!clientId || !clientSecret || !projectId) {
                    alert('Please fill in all credential fields');
                    return;
                }
                
                fetch('/api/save-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        client_id: clientId,
                        client_secret: clientSecret,
                        project_id: projectId
                    })
                })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('✅ Credentials saved successfully!');
                        showMainDashboard();
                    } else {
                        alert('❌ Failed to save credentials: ' + data.error);
                    }
                })
                .catch(err => {
                    alert('Failed to save credentials');
                    console.error('Save error:', err);
                });
            }

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
                        fetch('/api/status')
                        .then(r => r.json())
                        .then(status => {
                            if (status.environment_check.has_client_id && status.environment_check.has_client_secret) {
                                showMainDashboard();
                            } else {
                                document.getElementById('setup-content').style.display = 'block';
                            }
                        });
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

            function refreshStatus() {
                fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    const statusDiv = document.getElementById('system-status');
                    statusDiv.innerHTML = `
                        <p><strong>Google APIs:</strong> ${data.google_apis_available ? '✅' : '❌'}</p>
                        <p><strong>PDF Processing:</strong> ${data.pdf_processing_available ? '✅' : '❌'}</p>
                        <p><strong>Credentials:</strong> ${data.environment_check.has_client_id ? '✅' : '❌'}</p>
                        <p><strong>Current User:</strong> ${data.current_user || 'Not authenticated'}</p>
                        <p><strong>Gmail Service:</strong> ${data.gmail_service_active ? '✅' : '❌'}</p>
                        <p><strong>Drive Service:</strong> ${data.drive_service_active ? '✅' : '❌'}</p>
                        <p><strong>Sheets Service:</strong> ${data.sheets_service_active ? '✅' : '❌'}</p>
                        <p><strong>Railway:</strong> ${data.railway_environment ? '✅' : '❌'}</p>
                        <p><strong>Processed Emails:</strong> ${data.auto_sync_status.processed_emails}</p>
                    `;
                    
                    // Update scan button states
                    const fullScanBtn = document.getElementById('full-scan-btn');
                    const incrementalScanBtn = document.getElementById('incremental-scan-btn');
                    const startAutoSyncBtn = document.getElementById('start-auto-sync-btn');
                    const stopAutoSyncBtn = document.getElementById('stop-auto-sync-btn');
                    
                    if (data.gmail_service_active && data.drive_service_active) {
                        fullScanBtn.disabled = false;
                        incrementalScanBtn.disabled = false;
                        startAutoSyncBtn.disabled = false;
                        fullScanBtn.textContent = '📊 Test Scan (100 emails)';
                        incrementalScanBtn.textContent = '🔄 Quick Test (50 emails)';
                    } else {
                        fullScanBtn.disabled = true;
                        incrementalScanBtn.disabled = true;
                        startAutoSyncBtn.disabled = true;
                        fullScanBtn.textContent = '📊 Authentication Required';
                        incrementalScanBtn.textContent = '🔄 Authentication Required';
                    }
                    
                    // Update auto-sync status
                    const autoSyncStatusDiv = document.getElementById('auto-sync-status');
                    const indicator = data.auto_sync_status.active ? 
                        '<span class="auto-sync-indicator sync-active"></span>Auto-sync active' :
                        '<span class="auto-sync-indicator sync-inactive"></span>Auto-sync inactive';
                    
                    autoSyncStatusDiv.innerHTML = `
                        <p>${indicator}</p>
                        <p><small>Last full scan: ${data.auto_sync_status.last_full_scan || 'Never'}</small></p>
                    `;
                    
                    stopAutoSyncBtn.disabled = !data.auto_sync_status.active;
                    
                    // Update drive status
                    const driveStatusDiv = document.getElementById('drive-status');
                    if (data.auto_sync_status.drive_folders && Object.keys(data.auto_sync_status.drive_folders).length > 0) {
                        driveStatusDiv.innerHTML = `
                            <p>✅ Drive folders configured</p>
                            <p><small>${Object.keys(data.auto_sync_status.drive_folders).length} folders created</small></p>
                        `;
                    } else {
                        driveStatusDiv.innerHTML = '<p>❌ Drive folders not setup</p>';
                    }
                    
                    // Update logs
                    if (data.recent_logs && data.recent_logs.length > 0) {
                        const logsDiv = document.getElementById('logs-container');
                        logsDiv.innerHTML = data.recent_logs.map(log => 
                            `<div class="log-entry log-${log.level}">[${log.timestamp}] ${log.message}</div>`
                        ).join('');
                    }
                })
                .catch(err => {
                    console.error('Status error:', err);
                    document.getElementById('system-status').innerHTML = '<p style="color: red;">Failed to load status</p>';
                });
            }

            function setupGoogleAuth() {
                fetch('/api/start-oauth', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('oauth-section').classList.remove('hidden');
                        document.getElementById('auth-url').innerHTML = 
                            `<a href="${data.auth_url}" target="_blank">${data.auth_url}</a>`;
                        document.getElementById('setup-btn').textContent = '⏳ Waiting for Authorization...';
                        document.getElementById('setup-btn').disabled = true;
                    } else {
                        if (data.error.includes('not configured')) {
                            alert('Please set up your Google API credentials first');
                            showSetupSection();
                        } else {
                            alert('Failed to start OAuth: ' + data.error);
                        }
                    }
                })
                .catch(err => {
                    alert('OAuth setup failed');
                    console.error('OAuth error:', err);
                });
            }

            function completeAuth() {
                const authCode = document.getElementById('auth-code').value;
                if (!authCode) {
                    alert('Please enter the authorization code');
                    return;
                }
                
                fetch('/api/complete-oauth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ auth_code: authCode })
                })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('Authentication successful! Email: ' + data.email);
                        document.getElementById('oauth-section').classList.add('hidden');
                        document.getElementById('setup-btn').textContent = '✅ Google APIs Connected';
                        document.getElementById('setup-btn').disabled = true;
                        refreshStatus();
                    } else {
                        alert('Authentication failed: ' + data.error);
                    }
                })
                .catch(err => {
                    alert('Authentication completion failed');
                    console.error('Auth completion error:', err);
                });
            }

            function startFullScan() {
                document.getElementById('scan-results').innerHTML = '<p>🔄 Running test scan (100 emails)...</p>';
                
                fetch('/api/scan-emails', { 
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ full_scan: true, max_emails: 100 })  // Limited for testing
                })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('scan-results').innerHTML = 
                            `<p>✅ Full scan completed! Found ${data.resumes_found || 0} resumes in ${data.emails_scanned || 0} emails.</p>`;
                        
                        if (data.categories) {
                            updateCategoryStats(data.categories);
                        }
                        if (data.domain_statistics) {
                            updateDomainStatistics(data.domain_statistics);
                        }
                        if (data.domain_statistics) {
                            updateDomainStatistics(data.domain_statistics);
                        }
                    } else {
                        document.getElementById('scan-results').innerHTML = 
                            `<p style="color: red;">❌ Scan failed: ${data.error}</p>`;
                    }
                    refreshStatus();
                })
                .catch(err => {
                    document.getElementById('scan-results').innerHTML = 
                        '<p style="color: red;">❌ Scan request failed</p>';
                    console.error('Scan error:', err);
                });
            }

            function startIncrementalScan() {
                document.getElementById('scan-results').innerHTML = '<p>🔄 Running incremental scan...</p>';
                
                fetch('/api/scan-emails', { 
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ full_scan: false, max_emails: 50 })
                })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('scan-results').innerHTML = 
                            `<p>✅ Incremental scan completed! Found ${data.resumes_found || 0} new resumes in ${data.emails_scanned || 0} emails.</p>`;
                        
                        if (data.categories) {
                            updateCategoryStats(data.categories);
                        }
                    } else {
                        document.getElementById('scan-results').innerHTML = 
                            `<p style="color: red;">❌ Scan failed: ${data.error}</p>`;
                    }
                    refreshStatus();
                })
                .catch(err => {
                    document.getElementById('scan-results').innerHTML = 
                        '<p style="color: red;">❌ Scan request failed</p>';
                    console.error('Scan error:', err);
                });
            }

            function updateDomainStatistics(domainStats) {
                // This function can be used to display detailed domain statistics
                // in a separate section or modal if needed
                console.log('Domain Statistics:', domainStats);
            }

            function updateCategoryStats(data) {
                // Update score-based stats
                if (data.by_score_range) {
                    document.getElementById('high-score-count').textContent = data.by_score_range.high_score || 0;
                    document.getElementById('medium-score-count').textContent = data.by_score_range.medium_score || 0;
                    document.getElementById('low-score-count').textContent = data.by_score_range.low_score || 0;
                    document.getElementById('category-stats').classList.remove('hidden');
                }
                
                // Update domain stats
                if (data.by_domain) {
                    let vlsiCount = 0;
                    let softwareCount = 0;
                    let hardwareCount = 0;
                    
                    Object.keys(data.by_domain).forEach(domain => {
                        if (domain.includes('vlsi') || domain.includes('digital') || domain.includes('analog') || 
                            domain.includes('physical') || domain.includes('memory') || domain.includes('asic') || domain.includes('fpga')) {
                            vlsiCount += data.by_domain[domain];
                        } else if (domain.includes('software') || domain.includes('embedded')) {
                            softwareCount += data.by_domain[domain];
                        } else if (domain.includes('hardware') || domain.includes('pcb') || domain.includes('test')) {
                            hardwareCount += data.by_domain[domain];
                        }
                    });
                    
                    document.getElementById('vlsi-domain-count').textContent = vlsiCount;
                    document.getElementById('software-domain-count').textContent = softwareCount;
                    document.getElementById('hardware-domain-count').textContent = hardwareCount;
                    document.getElementById('domain-stats').classList.remove('hidden');
                }
                
                // Update experience stats
                if (data.by_experience) {
                    document.getElementById('entry-exp-count').textContent = data.by_experience.entry || 0;
                    document.getElementById('mid-exp-count').textContent = data.by_experience.mid || 0;
                    document.getElementById('senior-exp-count').textContent = data.by_experience.senior || 0;
                    document.getElementById('experience-stats').classList.remove('hidden');
                }
            }

            function startAutoSync() {
                fetch('/api/start-auto-sync', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('✅ Auto-sync started! Will scan every 2 hours.');
                        refreshStatus();
                    } else {
                        alert('❌ Failed to start auto-sync: ' + data.error);
                    }
                })
                .catch(err => {
                    alert('Auto-sync start failed');
                    console.error('Auto-sync error:', err);
                });
            }

            function stopAutoSync() {
                fetch('/api/stop-auto-sync', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('⏹️ Auto-sync stopped.');
                        refreshStatus();
                    } else {
                        alert('❌ Failed to stop auto-sync: ' + data.error);
                    }
                })
                .catch(err => {
                    alert('Auto-sync stop failed');
                    console.error('Auto-sync error:', err);
                });
            }

            function setupDriveFolders() {
                fetch('/api/setup-drive-folders', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('✅ Drive folders setup completed!');
                        refreshStatus();
                    } else {
                        alert('❌ Failed to setup drive folders: ' + data.error);
                    }
                })
                .catch(err => {
                    alert('Drive folder setup failed');
                    console.error('Drive setup error:', err);
                });
            }

            function clearLogs() {
                fetch('/api/clear-logs', { method: 'POST' })
                .then(() => {
                    document.getElementById('logs-container').innerHTML = '<p>Logs cleared</p>';
                });
            }

            // Handle Enter key in password field
            document.getElementById('admin-password').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    authenticate();
                }
            });

            // Auto-refresh status every 30 seconds when authenticated
            setInterval(() => {
                if (document.getElementById('main-content').style.display !== 'none') {
                    refreshStatus();
                }
            }, 30000);
            </script>
        </body>
        </html>
        '''
        
        return render_template_string(template)
        
    except Exception as e:
        app.logger.error(f"❌ Dashboard error: {e}")
        return f"Dashboard temporarily unavailable: {str(e)}", 500

# API Routes
@app.route('/api/save-credentials', methods=['POST'])
def api_save_credentials():
    """Save Google API credentials"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        data = request.get_json()
        client_id = data.get('client_id', '').strip()
        client_secret = data.get('client_secret', '').strip()
        project_id = data.get('project_id', '').strip()
        
        if not client_id or not client_secret or not project_id:
            return jsonify({'success': False, 'error': 'All credential fields are required'})
        
        result = scanner.save_credentials(client_id, client_secret, project_id)
        return jsonify(result)
        
    except Exception as e:
        scanner.add_log(f"❌ Failed to save credentials: {e}", 'error')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/auth', methods=['POST'])
def api_auth():
    """Admin authentication"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            scanner.add_log("🔑 Admin authentication successful", 'info')
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            scanner.add_log("❌ Failed admin authentication attempt", 'warning')
            return jsonify({'success': False, 'message': 'Invalid password'})
    except Exception as e:
        scanner.add_log(f"❌ Authentication error: {e}", 'error')
        return jsonify({'success': False, 'message': f'Authentication error: {str(e)}'})

@app.route('/api/status')
def api_status():
    """Get system status"""
    try:
        status = scanner.get_system_status()
        status['timestamp'] = datetime.now().isoformat()
        status['railway_environment'] = bool(os.environ.get('RAILWAY_ENVIRONMENT'))
        
        return jsonify(status)
    except Exception as e:
        scanner.add_log(f"❌ Status check failed: {e}", 'error')
        return jsonify({'error': f'Status check failed: {str(e)}'}), 500

@app.route('/api/start-oauth', methods=['POST'])
def api_start_oauth():
    """Start OAuth flow"""
    try:
        result = scanner.start_oauth_flow()
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"❌ OAuth start failed: {e}", 'error')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/complete-oauth', methods=['POST'])
def api_complete_oauth():
    """Complete OAuth flow"""
    try:
        data = request.get_json()
        auth_code = data.get('auth_code', '')
        
        if not auth_code:
            return jsonify({'success': False, 'error': 'Authorization code required'})
            
        result = scanner.complete_oauth_flow(auth_code)
        return jsonify(result)
    except Exception as e:
        scanner.add_log(f"❌ OAuth completion failed: {e}", 'error')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scan-emails', methods=['POST'])
def api_scan_emails():
    """Scan emails for resumes with Drive integration"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        if not scanner.gmail_service:
            return jsonify({'success': False, 'error': 'Gmail authentication required'})
            
        if not scanner.drive_service:
            return jsonify({'success': False, 'error': 'Google Drive authentication required'})
        
        # Get scan parameters
        data = request.get_json() if request.is_json else {}
        max_emails = data.get('max_emails', 100)
        full_scan = data.get('full_scan', False)
        
        scanner.add_log(f"📧 Starting {'FULL' if full_scan else 'INCREMENTAL'} Gmail scan", 'info')
        
        # Perform real Gmail scan with Drive integration
        result = scanner.scan_gmail_for_resumes(max_emails, full_scan)
        
        return jsonify(result)
        
    except Exception as e:
        scanner.add_log(f"❌ Email scan API failed: {e}", 'error')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/start-auto-sync', methods=['POST'])
def api_start_auto_sync():
    """Start auto-sync process"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        result = scanner.start_auto_sync()
        return jsonify(result)
        
    except Exception as e:
        scanner.add_log(f"❌ Auto-sync start failed: {e}", 'error')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stop-auto-sync', methods=['POST'])
def api_stop_auto_sync():
    """Stop auto-sync process"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        result = scanner.stop_auto_sync_process()
        return jsonify(result)
        
    except Exception as e:
        scanner.add_log(f"❌ Auto-sync stop failed: {e}", 'error')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/setup-drive-folders', methods=['POST'])
def api_setup_drive_folders():
    """Setup Google Drive folder structure"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        result = scanner.setup_drive_folders()
        return jsonify(result)
        
    except Exception as e:
        scanner.add_log(f"❌ Drive folder setup failed: {e}", 'error')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-logs', methods=['POST'])
def api_clear_logs():
    """Clear system logs"""
    try:
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
            
        scanner.logs.clear()
        scanner.add_log("🗑️ Logs cleared", 'info')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test')
def api_test():
    """Simple API test endpoint"""
    return jsonify({
        'message': 'VLSI Resume Scanner API with Auto-Sync is working on Railway!',
        'timestamp': datetime.now().isoformat(),
        'status': 'success',
        'railway_environment': bool(os.environ.get('RAILWAY_ENVIRONMENT')),
        'features': {
            'google_apis': GOOGLE_APIS_AVAILABLE,
            'pdf_processing': PDF_PROCESSING_AVAILABLE,
            'docx_processing': DOCX_PROCESSING_AVAILABLE,
            'auto_sync': True,
            'drive_integration': True
        }
    })

# RAILWAY FIX 9: Error handlers for better Railway compatibility
@app.errorhandler(404)
def not_found(error):
    app.logger.warning(f"🔍 404 Error: {request.url}")
    return jsonify({
        'error': 'Endpoint not found',
        'railway_status': 'running',
        'available_endpoints': ['/', '/health', '/startup', '/api/test', '/api/scan-emails', '/api/start-auto-sync']
    }), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"💥 500 Error: {error}")
    return jsonify({
        'error': 'Internal server error',
        'railway_status': 'error',
        'message': 'Please check Railway logs for details'
    }), 500

@app.errorhandler(TimeoutError)
def timeout_error(error):
    app.logger.error(f"⏰ Timeout Error: {error}")
    return jsonify({
        'error': 'Request timeout',
        'railway_status': 'timeout',
        'message': 'Operation took too long - try again'
    }), 504

# Initialize scanner on startup
scanner.add_log("🚀 VLSI Resume Scanner with Auto-Sync initialized for Railway", 'info')
scanner.add_log(f"📊 Google APIs available: {GOOGLE_APIS_AVAILABLE}", 'info')
scanner.add_log(f"📄 PDF processing available: {PDF_PROCESSING_AVAILABLE}", 'info')

# RAILWAY FIX 10: Proper main execution
if __name__ == '__main__':
    # Railway deployment configuration
    PORT = int(os.environ.get('PORT', 5000))
    
    if os.environ.get('RAILWAY_ENVIRONMENT'):
        app.logger.info("🚅 Starting on Railway...")
        app.run(
            host='0.0.0.0',
            port=PORT,
            debug=False,  # Never use debug=True in production
            threaded=True
        )
    else:
        # Local development
        app.logger.info("💻 Starting locally...")
        app.run(
            debug=True,
            host='0.0.0.0',
            port=PORT
        )
