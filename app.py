from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
import string
import ssl
import os
import subprocess
import requests
import threading
import time
from flask_cors import CORS
import logging
import json
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta
from dotenv import load_dotenv

def login_required(f):
    def decorated_function(*args, **kwargs):
        print(f"LOGIN CHECK: Checking {f.__name__}")
        
        if 'customer_id' not in session:
            print("REDIRECT: No login found")
            return redirect(url_for('login'))
        
        # Update last activity time on every request (keeps session alive)
        from datetime import datetime
        session['last_activity'] = datetime.utcnow().isoformat()
        
        print("ACCESS GRANTED: Login found")
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

load_dotenv()

app = Flask(__name__)
CORS(app)

TUNNEL_PORT_START = int(os.getenv('TUNNEL_PORT_START', 8000))
TUNNEL_PORT_END = int(os.getenv('TUNNEL_PORT_END', 9999))

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)  # Fallback max time
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Security
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)


def generate_registration_key():
    """Generate a secure registration key"""
    # Format: PV-XXXX-XXXX-XXXX
    chars = string.ascii_uppercase + string.digits
    key_parts = []
    for i in range(3):
        part = ''.join(secrets.choice(chars) for _ in range(4))
        key_parts.append(part)
    return f"PV-{'-'.join(key_parts)}"

def initialize_hub():
    """Initialize hub with master registration key if not exists"""
    hub = HubConfiguration.query.filter_by(is_active=True).first()
    if not hub:
        hub = HubConfiguration(
            hub_name="PacketViper Enterprise Hub",
            master_registration_key=generate_registration_key(),
            hub_port=7700
        )
        db.session.add(hub)
        db.session.commit()
    return hub

def create_customer_user(customer_id, username, password, email=None, role='admin'):
    """Create a new customer user with hashed password"""
    password_hash = generate_password_hash(password)
    user = CustomerUser(
        customer_id=customer_id,
        username=username,
        password_hash=password_hash,
        email=email,
        role=role
    )
    return user

def setup_ssl_context():
    """Setup SSL context for HTTPS"""
    ssl_dir = "ssl"
    cert_file = os.path.join(ssl_dir, "hub_cert.pem")
    key_file = os.path.join(ssl_dir, "hub_key.pem")
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.error("❌ SSL certificates not found!")
        logger.error(f"Expected files: {cert_file}, {key_file}")
        logger.error("Run: python generate_ssl_cert.py")
        return None
    
    try:
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        
        # Security settings
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        logger.info(f"✅ SSL context loaded successfully")
        logger.info(f"📄 Certificate: {cert_file}")
        logger.info(f"🔑 Private Key: {key_file}")
        
        return context
        
    except Exception as e:
        logger.error(f"❌ Error setting up SSL context: {e}")
        return None

class DeviceMonitor:
    """Background service for real-time device monitoring"""
    
    def __init__(self, app, device_manager, db):
        self.app = app
        self.device_manager = device_manager
        self.db = db
        self.running = False
        self.monitor_thread = None
        self.check_interval = 30  # Check every 30 seconds
        
    def start_monitoring(self):
        """Start the background monitoring thread"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            return  # Already running
            
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, 
            name="DeviceMonitor", 
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("✅ Real-time device monitoring started")
        
    def stop_monitoring(self):
        """Stop the background monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("🛑 Device monitoring stopped")
        
    def _monitor_loop(self):
        """Main monitoring loop that runs in background"""
        logger.info(f"🔍 Device monitoring loop started (checking every {self.check_interval}s)")
        
        while self.running:
            try:
                with self.app.app_context():
                    self._check_all_devices()
            except Exception as e:
                logger.error(f"❌ Error in device monitoring loop: {e}")
            
            # Sleep in small chunks so we can exit quickly when stopped
            for _ in range(self.check_interval):
                if not self.running:
                    break
                time.sleep(1)
                
    def _check_all_devices(self):
        """Check status of all active devices - immediate database updates"""
        devices = SecurityDevice.query.filter_by(is_active=True).all()
        
        for device in devices:
            if not device.ip_address:
                # No IP means device is still being configured
                if device.connection_status != 'pending':
                    device.connection_status = 'pending'
                    device.last_seen = datetime.utcnow()
                    try:
                        self.db.session.commit()
                        logger.debug(f"📝 Updated {device.device_name} to pending")
                    except Exception as e:
                        logger.error(f"❌ Error updating {device.device_name} to pending: {e}")
                        self.db.session.rollback()
                continue
                
            try:
                # Store the old status for comparison
                old_status = device.connection_status
                
                # Check if device is registered with hub
                hub = HubConfiguration.query.filter_by(is_active=True).first()
                if not hub:
                    # No hub configured, keep as pending
                    if device.connection_status != 'pending':
                        device.connection_status = 'pending'
                        device.last_seen = datetime.utcnow()
                        try:
                            self.db.session.commit()
                            logger.debug(f"📝 Updated {device.device_name} to pending (no hub)")
                        except Exception as e:
                            logger.error(f"❌ Error updating {device.device_name}: {e}")
                            self.db.session.rollback()
                    continue
                
                # Test device connection
                is_online = self._test_device_simple(device)
                logger.debug(f"🔍 Device {device.device_name} test result: {is_online}")
                
                # Determine new status
                if is_online:
                    new_status = 'connected'
                else:
                    # Only mark as disconnected if it was previously connected
                    if old_status == 'connected':
                        new_status = 'disconnected'
                    elif old_status in ['pending', None]:
                        new_status = 'pending'  # Keep pending until first connection
                    else:
                        new_status = 'disconnected'
                
                # Update device status immediately
                device.connection_status = new_status
                device.last_seen = datetime.utcnow()
                if is_online:
                    device.last_heartbeat = datetime.utcnow()
                
                # Commit this device's changes immediately
                try:
                    self.db.session.commit()
                    logger.debug(f"📝 Updated {device.device_name}: {old_status} → {new_status}")
                except Exception as e:
                    logger.error(f"❌ Error committing {device.device_name} status: {e}")
                    self.db.session.rollback()
                    continue
                
                # Log meaningful status changes AFTER successful commit
                if old_status == 'connected' and new_status == 'disconnected':
                    logger.warning(f"🔴 Device {device.device_name} went OFFLINE")
                    
                    try:
                        alert_event = SecurityEvent(
                            device_id=device.device_id,
                            event_type='device_offline',
                            event_description=f'Device {device.device_name} went offline',
                            severity_level='warning'
                        )
                        self.db.session.add(alert_event)
                        self.db.session.commit()
                        logger.debug(f"📝 Created offline event for {device.device_name}")
                    except Exception as e:
                        logger.error(f"❌ Error creating offline event: {e}")
                        self.db.session.rollback()
                    
                elif old_status in ['disconnected', 'pending'] and new_status == 'connected':
                    logger.info(f"✅ Device {device.device_name} came ONLINE")
                    
                    try:
                        recovery_event = SecurityEvent(
                            device_id=device.device_id,
                            event_type='device_online',
                            event_description=f'Device {device.device_name} came online',
                            severity_level='info'
                        )
                        self.db.session.add(recovery_event)
                        self.db.session.commit()
                        logger.debug(f"📝 Created online event for {device.device_name}")
                    except Exception as e:
                        logger.error(f"❌ Error creating online event: {e}")
                        self.db.session.rollback()
                    
            except Exception as e:
                logger.error(f"❌ Error monitoring device {device.device_id}: {e}")
                # Don't change pending devices to disconnected on errors
                if device.connection_status not in ['pending']:
                    device.connection_status = 'disconnected'
                    device.last_seen = datetime.utcnow()
                    try:
                        self.db.session.commit()
                        logger.debug(f"📝 Forced {device.device_name} to disconnected due to error")
                    except Exception as commit_e:
                        logger.error(f"❌ Error forcing {device.device_name} to disconnected: {commit_e}")
                        self.db.session.rollback()

    def _test_device_simple(self, device):
        """Simple binary test - returns True if device responds, False otherwise"""
        try:
            # Get hub config
            hub = HubConfiguration.query.filter_by(is_active=True).first()
            if not hub:
                return False
            
            # Quick HTTP test with very short timeout
            response = requests.get(
                f"http://{device.ip_address}:{device.port}/camera_status", 
                timeout=3,  # Very short timeout
                headers={
                    'X-Hub-ID': 'CyberPhysical Hub',
                    'X-Registration-Key': hub.master_registration_key
                }
            )
            
            # Any HTTP response means device is online
            logger.debug(f"✅ Device {device.device_name} responded with status {response.status_code}")
            return True
            
        except requests.exceptions.Timeout:
            logger.debug(f"⏱️ Device {device.device_name} timed out")
            return False
        except requests.exceptions.ConnectionError:
            logger.debug(f"🔌 Device {device.device_name} connection error")
            return False
        except Exception as e:
            logger.debug(f"❌ Device {device.device_name} error: {e}")
            return False

class TunnelDetector:
    """Detects new SSH tunnels and creates pending devices"""
    
    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.running = False
        self.detection_thread = None
        self.check_interval = 10  # Check every 10 seconds
        
    def start_detection(self):
        """Start tunnel detection"""
        if self.detection_thread and self.detection_thread.is_alive():
            return
            
        self.running = True
        self.detection_thread = threading.Thread(
            target=self._detection_loop,
            name="TunnelDetector", 
            daemon=True
        )
        self.detection_thread.start()
        logger.info("🔍 Tunnel detection started")
        
    def stop_detection(self):
        """Stop tunnel detection"""
        self.running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=5)
        logger.info("🛑 Tunnel detection stopped")
        
    def _detection_loop(self):
        """Main detection loop"""
        logger.info(f"🔍 Tunnel detection loop started (checking every {self.check_interval}s)")
        
        while self.running:
            try:
                with self.app.app_context():
                    self._scan_for_tunnels()
            except Exception as e:
                logger.error(f"❌ Error in tunnel detection: {e}")
            
            for _ in range(self.check_interval):
                if not self.running:
                    break
                time.sleep(1)
                
    def _scan_for_tunnels(self):
        """Scan for active SSH tunnels and create pending devices"""
        import subprocess
        
        try:
            # Get list of listening ports (SSH tunnels)
            result = subprocess.run(['sudo', 'netstat', '-tlnp'], capture_output=True, text=True)
            lines = result.stdout.split('\n')

            # Find active tunnel ports
            active_tunnel_ports = set()
            
            for line in lines:
                if ('sshd:' in line and ':' in line) or ('device_' in line and ':' in line):
                    parts = line.split()
                    for part in parts:
                        if ':' in part:
                            try:
                                port = int(part.split(':')[-1])
                            except ValueError:
                                continue
                            if TUNNEL_PORT_START <= port <= TUNNEL_PORT_END:
                                active_tunnel_ports.add(port)
                                logger.info(f"🎯 Detected active tunnel on port {port}")
                                self._handle_detected_tunnel(port)
            
            # NEW CODE: Update devices with missing tunnels
            all_tunnel_devices = SecurityDevice.query.filter(SecurityDevice.tunnel_port.isnot(None)).all()
            
            for device in all_tunnel_devices:
                if device.tunnel_port not in active_tunnel_ports:
                    # Tunnel is gone - mark as disconnected
                    if device.tunnel_status != 'disconnected':
                        logger.warning(f"🔴 Tunnel disappeared for {device.device_name} (port {device.tunnel_port})")
                        device.tunnel_status = 'disconnected'
                        device.connection_status = 'disconnected'
                        device.last_seen = datetime.utcnow()
                        self.db.session.commit()
                else:
                    # Tunnel is active - mark as connected
                    if device.tunnel_status != 'connected':
                        logger.info(f"✅ Tunnel restored for {device.device_name} (port {device.tunnel_port})")
                        device.tunnel_status = 'connected'
                        if device.approval_status == 'approved':
                            device.connection_status = 'connected'
                        device.last_seen = datetime.utcnow()
                        self.db.session.commit()
            
            logger.info(f"🔍 Scan complete. Found {len(active_tunnel_ports)} active tunnels")
                                    
        except Exception as e:
            logger.error(f"⚠️ Error scanning for tunnels: {e}")
            
    def _handle_detected_tunnel(self, tunnel_port):
        """Handle a newly detected tunnel"""
        # Check if device already exists for this tunnel port
        existing_device = SecurityDevice.query.filter_by(tunnel_port=tunnel_port).first()
        
        if existing_device:
            # Update existing device tunnel status, but preserve approval status
            if existing_device.tunnel_status != 'connected':
                existing_device.tunnel_status = 'connected'
                existing_device.last_seen = datetime.utcnow()
                
                # IMPORTANT: Don't change connection_status if device is already approved
                if existing_device.approval_status == 'approved':
                    # Keep approved devices as connected
                    if existing_device.connection_status != 'connected':
                        existing_device.connection_status = 'connected'
                        logger.info(f"✅ Restored approved device {existing_device.device_name} to connected status")
                
                self.db.session.commit()
                logger.info(f"✅ Updated tunnel status for device {existing_device.device_name}")
            return
            
        # Create new pending device for unknown tunnel
        try:
            # Get device info through tunnel
            device_info = self._probe_tunnel_device(tunnel_port)
            
            new_device = SecurityDevice(
                device_name=device_info.get('name', f'Unknown Device (Port {tunnel_port})'),
                device_type=device_info.get('type', 'Unknown'),
                model_number=device_info.get('model', 'Unknown'),
                serial_number=device_info.get('serial', None),
                description=f'Auto-detected via tunnel on port {tunnel_port}',
                tunnel_port=tunnel_port,
                tunnel_status='connected',
                connection_status='tunnel_pending',
                approval_status='pending',
                last_seen=datetime.utcnow()
            )
            
            self.db.session.add(new_device)
            self.db.session.commit()
            
            logger.info(f"🆕 Created pending device for tunnel port {tunnel_port}")
            
            # Create event
            event = SecurityEvent(
                device_id=new_device.device_id,
                event_type='tunnel_detected',
                event_description=f'New device tunnel detected on port {tunnel_port}',
                severity_level='info'
            )
            self.db.session.add(event)
            self.db.session.commit()
            
        except Exception as e:
            logger.error(f"❌ Error creating device for tunnel {tunnel_port}: {e}")
            
    def _probe_tunnel_device(self, tunnel_port):
        """Probe device through tunnel to get basic info"""
        try:
            response = requests.get(f'http://localhost:{tunnel_port}/device_info', timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
            
        # Fallback - basic info
        return {
            'name': f'Device-{tunnel_port}',
            'type': 'CyberPhysical',
            'model': 'Unknown'
        }

# Models mapped to your existing tables
class SecurityDevice(db.Model):
    __tablename__ = 'security_devices'
    
    device_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_name = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    model_number = db.Column(db.String(100), nullable=True)
    serial_number = db.Column(db.String(100), nullable=True)
    firmware_version = db.Column(db.String(50), nullable=True)
    installation_date = db.Column(db.Date, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=True)
    description = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(15), nullable=True)
    port = db.Column(db.Integer, default=5675, nullable=True)
    registration_key = db.Column(db.String(64), nullable=True)
    connection_status = db.Column(db.String(20), default='disconnected', nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    last_heartbeat = db.Column(db.DateTime, nullable=True)
    tunnel_port = db.Column(db.Integer, nullable=True)
    tunnel_status = db.Column(db.String(20), default='disconnected', nullable=True)
    approval_status = db.Column(db.String(20), default='approved', nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=True)
    
    # Define relationships
    locations = db.relationship('DeviceLocation', backref='device', lazy='dynamic')
    statuses = db.relationship('DeviceStatus', backref='device', lazy='dynamic')
    events = db.relationship('SecurityEvent', backref='device', lazy='dynamic')

class HubConfiguration(db.Model):
    __tablename__ = 'hub_configuration'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hub_name = db.Column(db.String(100), nullable=False)
    master_registration_key = db.Column(db.String(64), unique=True, nullable=False)
    hub_port = db.Column(db.Integer, default=7700)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Hub {self.hub_name}>'

class DeviceLocation(db.Model):
    __tablename__ = 'device_locations'
    
    location_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.Integer, db.ForeignKey('security_devices.device_id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=True)
    
    # Address/Description
    location_name = db.Column(db.String(200), nullable=True)  # "Main St & 5th Ave Traffic Box"
    address = db.Column(db.String(300), nullable=True)  # "1234 Main Street, City, State"
    location_type = db.Column(db.String(50), nullable=True)  # "traffic_box", "pump_station", etc.
    
    # GPS Coordinates (separate fields for better database handling)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    
    # Legacy fields (keep for compatibility)
    building_name = db.Column(db.String(100), nullable=True)
    floor_number = db.Column(db.String(20), nullable=True)
    room_number = db.Column(db.String(50), nullable=True)
    gps_coordinates = db.Column(db.String(100), nullable=True)  # Backup text format
    
    def __repr__(self):
        return f'<Location {self.location_name} ({self.latitude}, {self.longitude})>'

class DeviceStatus(db.Model):
    __tablename__ = 'device_status'
    
    status_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.Integer, db.ForeignKey('security_devices.device_id'), nullable=False)
    status_code = db.Column(db.String(50), nullable=False)
    status_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    details = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Status {self.status_code} for device {self.device_id}>'

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    
    event_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.Integer, db.ForeignKey('security_devices.device_id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    event_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    severity_level = db.Column(db.String(20), nullable=True)
    event_description = db.Column(db.Text, nullable=True)
    is_resolved = db.Column(db.Boolean, default=False, nullable=True)
    resolution_notes = db.Column(db.Text, nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=True)
    
    def __repr__(self):
        return f'<Event {self.event_type} for device {self.device_id}>'

class SystemUser(db.Model):
    __tablename__ = 'system_users'
    
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>'


# Add logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DeviceManager:
    """Manages authenticated communication with registered devices"""
    
    def __init__(self, app=None, db=None):
        self.app = app
        self.db = db
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
        self.db = db
    
    def make_device_request(self, device_id, endpoint, method='GET', data=None, timeout=10):
        """Make authenticated request to a registered device - HTTPS aware"""
        device = db.session.get(SecurityDevice, device_id)
        if not device:
            logger.error(f"Device {device_id} not found in database")
            return None, f"Device {device_id} not found"
        
        # Try tunnel first, fallback to direct IP
        if device.tunnel_port and device.tunnel_status == 'connected':
            # Tunnel connections go through localhost - check if hub is HTTPS
            protocol = "https" if app.config.get('SSL_ENABLED', False) else "http"
            url = f"{protocol}://localhost:{device.tunnel_port}{endpoint}"
            connection_type = "tunnel"
            logger.info(f"🔗 Using tunnel for device {device_id}: port {device.tunnel_port}")
        elif device.ip_address:
            # For direct IP, assume device uses HTTPS on port 443 or HTTP on configured port
            if device.port == 443:
                protocol = "https"
            elif hasattr(device, 'use_https') and device.use_https:
                protocol = "https"
            else:
                protocol = "http"
            
            url = f"{protocol}://{device.ip_address}:{device.port}{endpoint}"
            connection_type = "direct"
            logger.info(f"🔗 Using direct {protocol.upper()} for device {device_id}: {device.ip_address}")
        else:
            logger.error(f"Device {device_id} has no tunnel or IP address configured")
            return None, "No connection method available"
        
        # Get hub's registration key
        hub = HubConfiguration.query.filter_by(is_active=True).first()
        if not hub:
            logger.error("No active hub configuration found")
            return None, "Hub not configured"
        
        logger.info(f"🔑 === HUB SENDING HTTPS REQUEST ===")
        logger.info(f"🎯 Target: {device.device_name} ({device_id}) at {url}")
        logger.info(f"🔑 Hub master key: '{hub.master_registration_key}'")
        logger.info(f"Making {method} request to {device.device_name} ({device_id}) via {connection_type}: {endpoint}")
        
        # Authentication headers for device
        headers = {
            'X-Hub-ID': 'CyberPhysical Hub',
            'X-Registration-Key': hub.master_registration_key,
            'Content-Type': 'application/json',
            'User-Agent': 'PacketViper-Hub/1.0'
        }
        
        logger.info(f"📤 Headers being sent: {headers}")
        
        try:
            # Configure SSL verification
            verify_ssl = False  # Set to True for production with proper certificates
            
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=data, timeout=timeout, verify=verify_ssl)
            elif method.upper() == 'PUT':
                response = requests.put(url, headers=headers, json=data, timeout=timeout, verify=verify_ssl)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout, verify=verify_ssl)
            else:
                return None, f"Unsupported HTTP method: {method}"
            
            # Rest of your existing response handling code...
            logger.info(f"📥 Response status: {response.status_code}")
            logger.info(f"📥 Response headers: {dict(response.headers)}")
            logger.info(f"📥 Response content length: {len(response.content) if response.content else 0}")
            
            # Check for authentication rejection (empty response)
            if response.status_code == 204 and not response.content:
                logger.warning(f"🚫 Device {device_id} rejected authentication (204 empty response)")
                device.connection_status = 'auth_failed'
                device.last_seen = datetime.utcnow()
                self.db.session.commit()
                return None, "Authentication rejected by device"
            
            response.raise_for_status()
            
            # Update device status on successful connection
            device.connection_status = 'connected'
            device.last_seen = datetime.utcnow()
            device.last_heartbeat = datetime.utcnow()
            self.db.session.commit()
            
            # Try to parse JSON response
            try:
                return response.json(), None
            except ValueError:
                # Not JSON response
                return response.text, None
                
        except requests.exceptions.SSLError as e:
            error = f"SSL error connecting to device {device_id}: {e}"
            logger.error(error)
            device.connection_status = 'ssl_error'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return None, error
        except requests.exceptions.Timeout:
            error = f"Timeout connecting to device {device_id}"
            logger.error(error)
            device.connection_status = 'timeout'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return None, error
        except requests.exceptions.ConnectionError:
            error = f"Connection error to device {device_id}"
            logger.error(error)
            device.connection_status = 'disconnected'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return None, error
        except requests.exceptions.HTTPError as e:
            error = f"HTTP error from device {device_id}: {e}"
            logger.error(error)
            device.connection_status = 'error'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return None, error
        except Exception as e:
            error = f"Unexpected error with device {device_id}: {e}"
            logger.error(error)
            device.connection_status = 'error'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return None, error

    def get_all_devices_status(self):
        """Get status from all configured devices"""
        devices = SecurityDevice.query.filter_by(is_active=True).all()
        results = {}
        
        for device in devices:
            if not device.ip_address:
                continue
                
            # Get camera status
            camera_status, camera_error = self.make_device_request(device.device_id, '/camera_status')
            
            # Get switch status
            switch_status, switch_error = self.make_device_request(device.device_id, '/switch_status')
            
            # Get USB status
            usb_status, usb_error = self.make_device_request(device.device_id, '/usb_status')
            
            results[device.device_id] = {
                'name': device.device_name,
                'ip': device.ip_address,
                'port': device.port,
                'connection_status': device.connection_status,
                'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                'camera_status': camera_status,
                'switch_status': switch_status,
                'usb_status': usb_status,
                'errors': {
                    'camera': camera_error,
                    'switch': switch_error,
                    'usb': usb_error
                },
                'last_check': datetime.utcnow().isoformat()
            }
        return results

    def test_device_connection(self, device_id):
        """Test connection to a specific device with improved offline detection"""
        device = db.session.get(SecurityDevice, device_id)
        if not device:
            return False, "Device not found"
        
        if not device.ip_address:
            return False, "No IP address configured"
        
        try:
            # Get hub's master key for authentication
            hub = HubConfiguration.query.filter_by(is_active=True).first()
            if not hub:
                return False, "Hub not configured"
            
            # Try a simple HTTP request to device with shorter timeout
            response = requests.get(
                f"http://{device.ip_address}:{device.port}/camera_status", 
                timeout=5,  # Reduced from 10 to 5 seconds
                headers={
                    'X-Hub-ID': 'CyberPhysical Hub',
                    'X-Registration-Key': hub.master_registration_key
                }
            )
            
            # If we get any response, device is reachable
            if response.status_code in [200, 204, 404, 401]:  # Any HTTP response means device is up
                # Update device status
                device.connection_status = 'connected'
                device.last_seen = datetime.utcnow()
                device.last_heartbeat = datetime.utcnow()
                self.db.session.commit()
                return True, "Connection successful"
            else:
                # Unexpected status code
                device.connection_status = 'disconnected'
                device.last_seen = datetime.utcnow()
                self.db.session.commit()
                return False, f"HTTP {response.status_code}"
            
        except requests.exceptions.Timeout:
            device.connection_status = 'timeout'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return False, "Connection timeout"
            
        except requests.exceptions.ConnectionError:
            device.connection_status = 'disconnected'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return False, "Connection refused - device offline"
            
        except Exception as e:
            device.connection_status = 'disconnected'
            device.last_seen = datetime.utcnow()
            self.db.session.commit()
            return False, f"Connection error: {str(e)}"

class Customer(db.Model):
    __tablename__ = 'customers'
    
    customer_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_code = db.Column(db.String(20), unique=True, nullable=False)
    subscription_plan = db.Column(db.String(50), default='municipal')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    users = db.relationship('CustomerUser', backref='customer', lazy='dynamic')
    devices = db.relationship('SecurityDevice', backref='customer', lazy='dynamic')
    
    def __repr__(self):
        return f'<Customer {self.customer_name} ({self.customer_code})>'

class CustomerUser(db.Model):
    __tablename__ = 'customer_users'
    
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    role = db.Column(db.Enum('admin', 'viewer', 'operator'), default='viewer')
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<CustomerUser {self.username} ({self.role})>'

# Initialize device manager
device_manager = DeviceManager(app, db)

# Initialize real-time device monitoring
device_monitor = DeviceMonitor(app, device_manager, db)

# Initialize tunnel detector
tunnel_detector = TunnelDetector(app, db)

# Start monitoring when app starts (Flask 2.2+ compatible)
def start_background_monitoring():
    """Start device monitoring in a separate thread"""
    if not hasattr(app, '_monitoring_started'):
        device_monitor.start_monitoring()
        tunnel_detector.start_detection()
        app._monitoring_started = True

# Start monitoring after app is fully initialized
with app.app_context():
    # Small delay to ensure everything is ready
    import threading
    threading.Timer(2.0, start_background_monitoring).start()

# Stop monitoring when app shuts down
import atexit
atexit.register(device_monitor.stop_monitoring)
atexit.register(tunnel_detector.stop_detection)

# Routes
@app.route('/')
@login_required
def home():
    devices = SecurityDevice.query.filter_by(is_active=True).all()
    hub = HubConfiguration.query.filter_by(is_active=True).first()
    recent_events = SecurityEvent.query.order_by(SecurityEvent.event_timestamp.desc()).limit(5).all()
    
    return render_template('index.html', 
                         title='Security Operations Center',
                         devices=devices,
                         hub=hub,
                         recent_events=recent_events,
                         is_customer_view=False)

@app.route('/devices')
@login_required
def list_devices():
    devices = SecurityDevice.query.all()
    return render_template('devices/list.html', title='Security Devices', devices=devices)

@app.route('/initialize_hub')
@login_required
def initialize_hub_route():
    try:
        hub = initialize_hub()
        flash(f"Hub initialized! Registration Key: {hub.master_registration_key}", "success")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"Error initializing hub: {str(e)}", "error")
        return redirect(url_for('home'))

@app.route('/devices/<int:device_id>')
@login_required
def view_device(device_id):
    device = SecurityDevice.query.get_or_404(device_id)
    
    # Get live data from device if it has an IP
    camera_status = None
    switch_status = None
    usb_status = None
    errors = {}
    
    if device.ip_address and device.connection_status == 'connected':
        camera_status, errors['camera'] = device_manager.make_device_request(device_id, '/camera_status')
        switch_status, errors['switch'] = device_manager.make_device_request(device_id, '/switch_status')
        usb_status, errors['usb'] = device_manager.make_device_request(device_id, '/usb_status')
    
    # Get historical data
    locations = device.locations.all()
    statuses = device.statuses.order_by(DeviceStatus.status_timestamp.desc()).limit(5).all()
    events = device.events.order_by(SecurityEvent.event_timestamp.desc()).limit(10).all()
    
    return render_template('devices/view.html', 
                         title=f'Device: {device.device_name}',
                         device=device,
                         locations=locations,
                         statuses=statuses,
                         events=events,
                         camera_status=camera_status,
                         switch_status=switch_status,
                         usb_status=usb_status,
                         errors=errors)

@app.route('/events')
@login_required
def list_events():
    events = SecurityEvent.query.order_by(SecurityEvent.event_timestamp.desc()).all()
    return render_template('events/list.html', title='Security Events', events=events)

@app.route('/devices/add', methods=['GET', 'POST'])
@login_required
def add_device():
    if request.method == 'POST':
        try:
            # Get the hub's registration key
            hub = db.session.query(HubConfiguration).filter_by(is_active=True).first()
            if not hub:
                flash("Error: Hub not initialized. Please initialize hub first.", "error")
                return redirect(url_for('add_device'))
            
            # Create new device
            device = SecurityDevice(
                device_name=request.form['device_name'],
                device_type=request.form['device_type'],
                model_number=request.form['model'],  # Changed from model_number
                serial_number=request.form.get('serial_number'),
                description=request.form.get('description'),
                
                # NEW CONNECTION FIELDS:
                ip_address=request.form['ip_address'],
                port=int(request.form.get('port', 5675)),
                registration_key=hub.master_registration_key,
                connection_status='pending'
            )
            
            # Handle location - we'll add this to the DeviceLocation table
            if request.form.get('location'):
                db.session.add(device)
                db.session.flush()  # Get the device_id
                
                location = DeviceLocation(
                    device_id=device.device_id,
                    building_name=request.form['location'],  # Store in building_name for now
                    room_number="",
                    floor_number="",
                    gps_coordinates=""
                )
                db.session.add(location)
            
            db.session.commit()
            
            flash(f"Device '{device.device_name}' added successfully!", "success")
            return redirect(url_for('list_devices'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding device: {str(e)}", "error")
            return redirect(url_for('add_device'))
    
    # GET request - show the form
    hub = HubConfiguration.query.filter_by(is_active=True).first()
    return render_template('devices/add.html', 
                         title='Add New Device',
                         hub=hub)
    
    # GET request - show the form
    # Get hub info for display
    hub = HubConfiguration.query.filter_by(is_active=True).first()
    return render_template('devices/add.html', 
                         title='Add New Device',
                         hub=hub)    

@app.route('/events/<int:event_id>')
@login_required
def view_event(event_id):
    event = SecurityEvent.query.get_or_404(event_id)
    return render_template('events/view.html', 
                           title=f'Event: {event.event_type}',
                           event=event)

@app.route('/admin/keys')
@login_required
def manage_keys():
    """Read-only key display for customers"""
    hub = HubConfiguration.query.filter_by(is_active=True).first()
    devices = SecurityDevice.query.all()
    
    return render_template('admin/keys.html', 
                         title='Registration Key Information',
                         hub=hub, 
                         devices=devices)

@app.route('/admin/emergency_key_reset', methods=['GET', 'POST'])
@login_required
def emergency_key_reset():
    """Emergency key reset - hidden route for support use"""
    if request.method == 'POST':
        admin_password = request.form.get('admin_password', '')
        
        # Simple admin password check (you can make this more secure)
        if admin_password != 'PacketViper2025!':  # Change this to whatever you want
            flash('Invalid admin password', 'error')
            return render_template('admin/emergency_reset.html')
        
        try:
            hub = HubConfiguration.query.filter_by(is_active=True).first()
            if not hub:
                hub = initialize_hub()
            
            old_key = hub.master_registration_key
            new_key = generate_registration_key()
            hub.master_registration_key = new_key
            
            # Update all devices to pending status
            devices = SecurityDevice.query.all()
            for device in devices:
                device.registration_key = new_key
                device.connection_status = 'pending'
            
            db.session.commit()
            
            flash(f'EMERGENCY RESET COMPLETE', 'success')
            flash(f'Old key: {old_key}', 'info')
            flash(f'New key: {new_key}', 'success')
            flash(f'All {len(devices)} devices must be reconfigured!', 'warning')
            
            return render_template('admin/emergency_reset.html', 
                                 reset_complete=True, 
                                 new_key=new_key, 
                                 old_key=old_key)
            
        except Exception as e:
            db.session.rollback()
            flash(f'Reset failed: {str(e)}', 'error')
            return render_template('admin/emergency_reset.html')
    
    # GET request - show the form
    return render_template('admin/emergency_reset.html')   

@app.route('/settings')
@login_required
def settings():
    """Main settings page"""
    hub = HubConfiguration.query.filter_by(is_active=True).first()
    devices = SecurityDevice.query.all()
    recent_events = SecurityEvent.query.order_by(SecurityEvent.event_timestamp.desc()).limit(10).all()
    
    return render_template('settings/index.html', 
                         title='System Settings',
                         hub=hub,
                         devices=devices,
                         recent_events=recent_events) 

@app.route('/api/devices/status')
@login_required
def get_devices_status():
    """Get status from all devices"""
    try:
        status = device_manager.get_all_devices_status()
        return {"success": True, "data": status}
    except Exception as e:
        logger.error(f"Error getting devices status: {e}")
        return {"success": False, "error": str(e)}, 500

@app.route('/api/devices/<int:device_id>/camera_status')
@login_required
def get_device_camera_status(device_id):
    """Get camera status from specific device"""
    data, error = device_manager.make_device_request(device_id, '/camera_status')
    if error:
        return {"success": False, "error": error}, 500
    return {"success": True, "data": data}

@app.route('/api/devices/<int:device_id>/switch_status')
@login_required
def get_device_switch_status(device_id):
    """Get switch status from specific device"""
    data, error = device_manager.make_device_request(device_id, '/switch_status')
    if error:
        return {"success": False, "error": error}, 500
    return {"success": True, "data": data}

@app.route('/api/devices/<int:device_id>/usb_status')
@login_required
def get_device_usb_status(device_id):
    """Get USB status from specific device"""
    data, error = device_manager.make_device_request(device_id, '/usb_status')
    if error:
        return {"success": False, "error": error}, 500
    return {"success": True, "data": data}

@app.route('/api/devices/<int:device_id>/test_connection')
@login_required
def test_device_connection(device_id):
    """Test connection to a specific device"""
    success, message = device_manager.test_device_connection(device_id)
    return {
        "success": success,
        "message": message,
        "device_id": device_id,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.route('/api/devices/test_all_connections')
@login_required
def test_all_device_connections():
    """Test authentication with all devices"""
    devices = SecurityDevice.query.filter_by(is_active=True).all()
    results = {}
    
    for device in devices:
        if device.ip_address:
            success, message = device_manager.test_device_connection(device.device_id)
            results[device.device_id] = {
                'device_name': device.device_name,
                'ip_address': device.ip_address,
                'authenticated': success,
                'message': message,
                'connection_status': device.connection_status
            }
    
    return {"success": True, "results": results}

@app.route('/devices/<int:device_id>/live_status')
@login_required
def device_live_status(device_id):
    """Get live status for a specific device (for device detail page)"""
    device = SecurityDevice.query.get_or_404(device_id)
    
    # Get live data from device
    camera_data, camera_error = device_manager.make_device_request(device_id, '/camera_status')
    switch_data, switch_error = device_manager.make_device_request(device_id, '/switch_status')
    usb_data, usb_error = device_manager.make_device_request(device_id, '/usb_status')
    
    # Get historical data
    locations = device.locations.all()
    statuses = device.statuses.order_by(DeviceStatus.status_timestamp.desc()).limit(5).all()
    events = device.events.order_by(SecurityEvent.event_timestamp.desc()).limit(10).all()
    
    return render_template('devices/view.html', 
                         title=f'Device: {device.device_name}',
                         device=device,
                         locations=locations,
                         statuses=statuses,
                         events=events,
                         camera_status=camera_data,
                         switch_status=switch_data,
                         usb_status=usb_data,
                         errors={
                             'camera': camera_error,
                             'switch': switch_error,
                             'usb': usb_error
                         })

@app.route('/devices/<int:device_id>/send_registration_key', methods=['POST'])
@login_required
def send_registration_key_to_device(device_id):
    """Send registration key to device for auto-configuration"""
    device = SecurityDevice.query.get_or_404(device_id)
    hub = HubConfiguration.query.filter_by(is_active=True).first()
    
    if not hub:
        flash("Error: Hub not configured", "error")
        return redirect(url_for('view_device', device_id=device_id))
    
    # Try to send registration key to device
    registration_data = {
        'registration_key': hub.master_registration_key
    }
    
    data, error = device_manager.make_device_request(
        device_id, 
        '/api/register', 
        method='POST', 
        data=registration_data
    )
    
    if error:
        flash(f"Failed to register device: {error}", "error")
    else:
        flash(f"Registration key sent to {device.device_name} successfully!", "success")
        device.connection_status = 'registered'
        db.session.commit()
    
    return redirect(url_for('view_device', device_id=device_id)) 

@app.route('/api/devices/<int:device_id>/log_access', methods=['POST'])
@login_required
def log_device_access(device_id):
    """Log when someone accesses a device remotely"""
    try:
        data = request.get_json()
        device = db.session.get(SecurityDevice, device_id)
        
        if device:
            # Log the access event
            event = SecurityEvent(
                device_id=device_id,
                event_type='remote_access',
                event_description=f'Remote access to {device.device_name} at {data.get("url", "unknown")}',
                severity_level='info'
            )
            db.session.add(event)
            db.session.commit()
            
            logger.info(f"Remote access logged for device {device_id} by user")
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error logging device access: {e}")
        return jsonify({'success': False, 'error': str(e)})   

@app.route('/devices/<int:device_id>/edit')
@login_required
def edit_device(device_id):
    """Show edit form for a specific device"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        flash('Device not found', 'error')
        return redirect(url_for('list_devices'))
    
    return render_template('devices/edit.html', 
                         title=f'Edit {device.device_name}',
                         device=device)

@app.route('/devices/<int:device_id>/update', methods=['POST'])
@login_required
def update_device(device_id):
    """Update device information"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        flash('Device not found', 'error')
        return redirect(url_for('list_devices'))
    
    try:
        # Update device fields
        device.device_name = request.form.get('device_name', '').strip()
        device.device_type = request.form.get('device_type', '').strip()
        device.model_number = request.form.get('model_number', '').strip()
        device.serial_number = request.form.get('serial_number', '').strip()
        device.description = request.form.get('description', '').strip()
        device.ip_address = request.form.get('ip_address', '').strip()
        device.port = int(request.form.get('port', 5675))
        device.is_active = 'is_active' in request.form
        
        # Handle location data
        location_text = request.form.get('location', '').strip()
        location_type = request.form.get('location_type', '').strip()
        address_search = request.form.get('address_search', '').strip()
        latitude = request.form.get('latitude', '').strip()
        longitude = request.form.get('longitude', '').strip()
        
        # Get or create device location record
        location = DeviceLocation.query.filter_by(device_id=device_id).first()
        if not location:
            location = DeviceLocation(device_id=device_id)
            db.session.add(location)
        
        # Update location fields
        location.building_name = location_text  # Keep legacy field
        location.location_name = location_text
        location.address = address_search if address_search else location_text
        location.location_type = location_type
        
        # Update GPS coordinates if provided
        if latitude and longitude:
            try:
                location.latitude = float(latitude)
                location.longitude = float(longitude)
                location.gps_coordinates = f"{latitude},{longitude}"  # Legacy format
                print(f"Saving GPS: {latitude}, {longitude}")  # Debug log
            except ValueError:
                print(f"Invalid GPS coordinates: {latitude}, {longitude}")
        
        db.session.commit()
        
        logger.info(f"Device {device_id} updated successfully")
        flash(f'Device "{device.device_name}" updated successfully!', 'success')
        
        return redirect(url_for('view_device', device_id=device_id))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating device {device_id}: {e}")
        flash(f'Error updating device: {str(e)}', 'error')
        return redirect(url_for('edit_device', device_id=device_id))

@app.route('/api/version')
def get_version():
    try:
        from version import __version__, __build__
        return jsonify({
            'version': __version__,
            'build': __build__,
            'success': True
        })
    except ImportError:
        return jsonify({
            'version': 'Unknown',
            'build': 'Unknown', 
            'success': False
        })       

@app.route('/map')
@login_required
def interactive_map():
    print("INSIDE INTERACTIVE_MAP FUNCTION")
    """Interactive map showing all device locations"""
    # Get all devices with their locations
    devices_with_locations = db.session.query(SecurityDevice, DeviceLocation)\
        .join(DeviceLocation, SecurityDevice.device_id == DeviceLocation.device_id)\
        .filter(SecurityDevice.is_active == True)\
        .filter(DeviceLocation.latitude.isnot(None))\
        .filter(DeviceLocation.longitude.isnot(None))\
        .all()
    
    # Format data for the map
    map_devices = []
    for device, location in devices_with_locations:
        map_devices.append({
            'device_id': device.device_id,
            'device_name': device.device_name,
            'device_type': device.device_type,
            'model_number': device.model_number,
            'connection_status': device.connection_status,
            'approval_status': device.approval_status, 
            'ip_address': device.ip_address,
            'port': device.port,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            'location_name': location.location_name,
            'address': location.address,
            'location_type': location.location_type,
            'latitude': location.latitude,
            'longitude': location.longitude
        })

    return render_template('map/index.html', 
                         title='Device Map',
                         devices=map_devices)

print(f"DEBUG: Map route function name: {interactive_map.__name__}")
print(f"DEBUG: Map route is wrapped: {hasattr(interactive_map, '__wrapped__')}")

@app.route('/api/devices/<int:device_id>/connection_info')
@login_required
def get_device_connection_info(device_id):
    """Get connection information for a device (tunnel vs direct IP)"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    return jsonify({
        'success': True,
        'device_id': device_id,
        'device_name': device.device_name,
        'tunnel_port': device.tunnel_port,
        'tunnel_status': device.tunnel_status,
        'ip_address': device.ip_address,
        'port': device.port,
        'connection_status': device.connection_status,
        'has_tunnel': bool(device.tunnel_port and device.tunnel_status == 'connected'),
        'has_direct_ip': bool(device.ip_address)
    })


@app.route('/proxy/<int:device_id>/', methods=['GET', 'POST'])
@app.route('/proxy/<int:device_id>/<path:path>', methods=['GET', 'POST'])
@login_required
def proxy_device(device_id, path=''):
    """Enhanced proxy with complete HTML rewriting"""

    logger.info(f"🔗 PROXY REQUEST: device_id={device_id}, path='{path}', query='{request.query_string.decode()}'")

    device = db.session.get(SecurityDevice, device_id)
    if not device or not device.tunnel_port:
        return "Device not found or no tunnel", 404
   
    import requests
   
    target_url = f"http://localhost:{device.tunnel_port}/{path}"
    if request.query_string:
        target_url += f"?{request.query_string.decode()}"

    # Handle streaming responses (like camera feeds) differently
    if 'stream' in path:
        try:
            logger.info(f"🎥 Attempting to stream from {target_url}")
            import requests
            response = requests.get(target_url, stream=True, timeout=10)
            logger.info(f"🎥 Stream response: {response.status_code} {response.headers.get('content-type')}")
            
            return Response(
                response.iter_content(chunk_size=1024),
                status=response.status_code,
                content_type=response.headers.get('content-type'),
            )
        except Exception as e:
            logger.error(f"🎥 Stream proxy error: {e}")
            return "Stream unavailable", 503
   
    if request.method == 'POST':
        response = requests.post(target_url, json=request.get_json(), timeout=10)
    else:
        response = requests.get(target_url, timeout=10)
   
    # If it's HTML, rewrite ALL the paths to use proxy
    if 'text/html' in response.headers.get('content-type', ''):
        content = response.text

        if 'motion_detection/toggle' in content:
            logger.info(f"🎯 Found motion_detection/toggle in HTML content")
            # Find the specific pattern
            import re
            toggle_patterns = re.findall(r'.{0,100}motion_detection/toggle.{0,100}', content, re.IGNORECASE)
            for pattern in toggle_patterns:
                logger.info(f"Toggle pattern: {repr(pattern)}")
        else:
            logger.info(f"❌ No motion_detection/toggle found in HTML")

        if 'stream_video' in content:
            logger.info(f"🎬 Found stream_video in HTML content")
            import re
            video_patterns = re.findall(r'.{0,100}stream_video.{0,100}', content, re.IGNORECASE)
            for pattern in video_patterns[:3]:  # Just show first 3 matches
                logger.info(f"Video pattern: {repr(pattern)}")
        else:
            logger.info(f"❌ No stream_video found in HTML")
            
                
        # Fix all static asset paths first
        content = content.replace('src="/static/', f'src="/proxy/{device_id}/static/')
        content = content.replace('href="/static/', f'href="/proxy/{device_id}/static/')
        content = content.replace('src="/thumbnails/', f'src="/proxy/{device_id}/thumbnails/')
        
        # Fix all the API endpoints that are failing
        content = content.replace('"/camera_status"', f'"/proxy/{device_id}/camera_status"')
        content = content.replace('"/switch_status"', f'"/proxy/{device_id}/switch_status"')
        content = content.replace('"/api/usb_devices"', f'"/proxy/{device_id}/api/usb_devices"')
        content = content.replace('"/maintenance_mode"', f'"/proxy/{device_id}/maintenance_mode"')
        content = content.replace('"/motion_status"', f'"/proxy/{device_id}/motion_status"')
        content = content.replace('"/motion_history"', f'"/proxy/{device_id}/motion_history"')
        content = content.replace('"/live/', f'"/proxy/{device_id}/live/')
        content = content.replace('"/stream_video/', f'"/proxy/{device_id}/stream_video/')
        content = content.replace('href="/live/', f'href="/proxy/{device_id}/live/')
        content = content.replace('href="/live/', f'href="/proxy/{device_id}/live/')
        content = content.replace("href='/live/", f"href='/proxy/{device_id}/live/")
        content = content.replace('window.location="/live/', f'window.location="/proxy/{device_id}/live/')
        content = content.replace("window.location='/live/", f"window.location='/proxy/{device_id}/live/")
        content = content.replace('location.href="/live/', f'location.href="/proxy/{device_id}/live/')
        content = content.replace("location.href='/live/", f"location.href='/proxy/{device_id}/live/")
        content = content.replace("openLiveStream('/live/", f"openLiveStream('/proxy/{device_id}/live/")
        content = content.replace('"/stream/', f'"/proxy/{device_id}/stream/')
        content = content.replace('src="camera', f'src="/proxy/{device_id}/camera')
        content = content.replace('"camera1"', f'"/proxy/{device_id}/camera1"')
        content = content.replace("'camera1'", f"'/proxy/{device_id}/camera1'")
        content = content.replace('fetch("/camera_status")', f'fetch("/proxy/{device_id}/camera_status")')
        content = content.replace("fetch('/camera_status')", f"fetch('/proxy/{device_id}/camera_status')")
        content = content.replace('$.get("/camera_status"', f'$.get("/proxy/{device_id}/camera_status"')
        content = content.replace("$.get('/camera_status'", f"$.get('/proxy/{device_id}/camera_status'")
        content = content.replace("fetch('/motion_detection/toggle',", f"fetch('/proxy/{device_id}/motion_detection/toggle',")
        content = content.replace('"/stream_video/', f'"/proxy/{device_id}/stream_video/')
        content = content.replace("openStreamPopup('/stream_video/", f"openStreamPopup('/proxy/{device_id}/stream_video/")
        content = content.replace("fetch('/email_config'", f"fetch('/proxy/{device_id}/email_config'")
        content = content.replace('fetch("/email_config"', f'fetch("/proxy/{device_id}/email_config"')
        content = content.replace("fetch('/email_config',", f"fetch('/proxy/{device_id}/email_config',")
        content = content.replace('fetch("/email_config",', f'fetch("/proxy/{device_id}/email_config",')
        content = content.replace('"/motion_status"', f'"/proxy/{device_id}/motion_status"')
        content = content.replace("'/motion_status'", f"'/proxy/{device_id}/motion_status'")
        content = content.replace('fetch("/api/update/check"', f'fetch("/proxy/{device_id}/api/update/check"')
        content = content.replace("'/api/update/check'", f"'/proxy/{device_id}/api/update/check'")
        content = content.replace('"/api/update/check"', f'"/proxy/{device_id}/api/update/check"')
        content = content.replace('"/motion_history"', f'"/proxy/{device_id}/motion_history"')
        content = content.replace('"/motion_history"', f'"/proxy/{device_id}/motion_history"')
        content = content.replace("'/motion_history'", f"'/proxy/{device_id}/motion_history'")
        content = content.replace('"/logs"', f'"/proxy/{device_id}/logs"')
        content = content.replace("'/logs'", f"'/proxy/{device_id}/logs'")
        content = content.replace('"/api/logs"', f'"/proxy/{device_id}/api/logs"')
        content = content.replace("'/api/logs'", f"'/proxy/{device_id}/api/logs'")
        content = content.replace('fetch("/logs"', f'fetch("/proxy/{device_id}/logs"')
        content = content.replace("fetch('/logs'", f"fetch('/proxy/{device_id}/logs'")
        content = content.replace('fetch("/system/logs"', f'fetch("/proxy/{device_id}/system/logs"')
        content = content.replace("fetch('/system/logs'", f"fetch('/proxy/{device_id}/system/logs'")
        content = content.replace('"/system/logs"', f'"/proxy/{device_id}/system/logs"')
        content = content.replace("'/system/logs'", f"'/proxy/{device_id}/system/logs'")
        content = content.replace('"/api/logs?', f'"/proxy/{device_id}/api/logs?')
        content = content.replace("'/api/logs?", f"'/proxy/{device_id}/api/logs?")
        content = content.replace('fetch("/api/logs?', f'fetch("/proxy/{device_id}/api/logs?')
        content = content.replace("fetch('/api/logs?", f"fetch('/proxy/{device_id}/api/logs?")
        content = content.replace('$.get("/api/logs?', f'$.get("/proxy/{device_id}/api/logs?')
        content = content.replace("$.get('/api/logs?", f"$.get('/proxy/{device_id}/api/logs?")
        content = content.replace('xhr.open("GET", "/api/logs?', f'xhr.open("GET", "/proxy/{device_id}/api/logs?')
        content = content.replace("xhr.open('GET', '/api/logs?", f"xhr.open('GET', '/proxy/{device_id}/api/logs?")
        content = content.replace('baseUrl + "/api/logs', f'baseUrl + "/proxy/{device_id}/api/logs')
        content = content.replace('"/api/logs"', f'"/proxy/{device_id}/api/logs"')
        content = content.replace("'/api/logs'", f"'/proxy/{device_id}/api/logs'")
        content = content.replace('url: "/api/logs', f'url: "/proxy/{device_id}/api/logs')
        content = content.replace("url: '/api/logs", f"url: '/proxy/{device_id}/api/logs")
        content = content.replace('endpoint: "/api/logs', f'endpoint: "/proxy/{device_id}/api/logs')
        content = content.replace("endpoint: '/api/logs", f"endpoint: '/proxy/{device_id}/api/logs")
        content = content.replace('apiUrl + "/logs', f'apiUrl + "/proxy/{device_id}/logs')
        content = content.replace("apiUrl + '/logs", f"apiUrl + '/proxy/{device_id}/logs")
        content = content.replace('"/download/', f'"/proxy/{device_id}/download/')
        content = content.replace("'/download/", f"'/proxy/{device_id}/download/")
                
        return content, response.status_code, dict(response.headers)

    elif 'javascript' in response.headers.get('content-type', '') or path.endswith('.js'):
        content = response.text
        logger.info(f"🔧 Rewriting JavaScript file: {path}")
        
        # Fix fetch() calls with single quotes
        content = content.replace("fetch('/camera_status')", f"fetch('/proxy/{device_id}/camera_status')")
        content = content.replace("fetch('/switch_status')", f"fetch('/proxy/{device_id}/switch_status')")
        content = content.replace("fetch('/api/usb_devices')", f"fetch('/proxy/{device_id}/api/usb_devices')")
        content = content.replace("fetch('/maintenance_mode')", f"fetch('/proxy/{device_id}/maintenance_mode')")
        content = content.replace("fetch('/motion_status')", f"fetch('/proxy/{device_id}/motion_status')")
        content = content.replace("fetch('/motion_history')", f"fetch('/proxy/{device_id}/motion_history')")
        content = content.replace("fetch('/motion_detection/toggle'", f"fetch('/proxy/{device_id}/motion_detection/toggle'")
        content = content.replace('fetch("/motion_detection/toggle"', f'fetch("/proxy/{device_id}/motion_detection/toggle"')
        content = content.replace("fetch('/motion_detection/toggle'", f"fetch('/proxy/{device_id}/motion_detection/toggle'")
        content = content.replace('fetch("/motion_detection/toggle"', f'fetch("/proxy/{device_id}/motion_detection/toggle"')
        content = content.replace("fetch('/email_config'", f"fetch('/proxy/{device_id}/email_config'")
        content = content.replace('fetch("/email_config"', f'fetch("/proxy/{device_id}/email_config"')
        content = content.replace("fetch('/email_config',", f"fetch('/proxy/{device_id}/email_config',")
        content = content.replace('fetch("/email_config",', f'fetch("/proxy/{device_id}/email_config",')
        content = content.replace("fetch('/api/update/check'", f"fetch('/proxy/{device_id}/api/update/check'")
        content = content.replace('fetch("/api/update/check"', f'fetch("/proxy/{device_id}/api/update/check"')
        content = content.replace("fetch('/api/update/perform'", f"fetch('/proxy/{device_id}/api/update/perform'")
        content = content.replace('fetch("/api/update/perform"', f'fetch("/proxy/{device_id}/api/update/perform"')
        content = content.replace("fetch('/api/update/preview'", f"fetch('/proxy/{device_id}/api/update/preview'")
        content = content.replace('fetch("/api/update/preview"', f'fetch("/proxy/{device_id}/api/update/preview"')
        content = content.replace("'/api/update/check'", f"'/proxy/{device_id}/api/update/check'")
        content = content.replace('"/api/update/check"', f'"/proxy/{device_id}/api/update/check"')
        content = content.replace("'/api/update/perform'", f"'/proxy/{device_id}/api/update/perform'")
        content = content.replace('"/api/update/perform"', f'"/proxy/{device_id}/api/update/perform"')
        content = content.replace("'/api/update/preview'", f"'/proxy/{device_id}/api/update/preview'")
        content = content.replace('"/api/update/preview"', f'"/proxy/{device_id}/api/update/preview"')
        content = content.replace('fetch("/camera_status")', f'fetch("/proxy/{device_id}/camera_status")')
        content = content.replace('fetch("/switch_status")', f'fetch("/proxy/{device_id}/switch_status")')
        content = content.replace('fetch("/api/usb_devices")', f'fetch("/proxy/{device_id}/api/usb_devices")')
        content = content.replace("const response = await fetch('/api/update/check',", f"const response = await fetch('/proxy/{device_id}/api/update/check',")
        content = content.replace("        const response = await fetch('/api/update/check', {", f"        const response = await fetch('/proxy/{device_id}/api/update/check', {{")
        content = content.replace("fetch('/api/update/status')", f"fetch('/proxy/{device_id}/api/update/status')")
        content = content.replace('"/api/logs"', f'"/proxy/{device_id}/api/logs"')
        content = content.replace("'/api/logs'", f"'/proxy/{device_id}/api/logs'")
        content = content.replace('"/api/logs?', f'"/proxy/{device_id}/api/logs?')
        content = content.replace("'/api/logs?", f"'/proxy/{device_id}/api/logs?")
        content = content.replace('url: "/api/logs', f'url: "/proxy/{device_id}/api/logs')
        content = content.replace("url: '/api/logs", f"url: '/proxy/{device_id}/api/logs")
        content = content.replace('endpoint: "/api/logs', f'endpoint: "/proxy/{device_id}/api/logs')
        content = content.replace("endpoint: '/api/logs", f"endpoint: '/proxy/{device_id}/api/logs")
        content = content.replace('baseUrl + "/api/logs', f'baseUrl + "/proxy/{device_id}/api/logs')
        content = content.replace("baseUrl + '/api/logs", f"baseUrl + '/proxy/{device_id}/api/logs")
        content = content.replace('href="/download/', f'href="/proxy/{device_id}/download/')
        content = content.replace("href='/download/", f"href='/proxy/{device_id}/download/")
    
        
        return content, response.status_code, dict(response.headers)
   
    return response.content, response.status_code, dict(response.headers)

@app.route('/api/logs')
@login_required
def redirect_logs_to_proxy():
    """Catch logs requests that didn't get proxied and redirect them"""
    # Get the referer to figure out which device this came from
    referer = request.headers.get('Referer', '')
    
    if '/proxy/' in referer:
        # Extract device_id from referer URL
        import re
        match = re.search(r'/proxy/(\d+)/', referer)
        if match:
            device_id = match.group(1)
            # Reconstruct the proper proxy URL with query parameters
            query_string = request.query_string.decode()
            proxy_url = f"/proxy/{device_id}/api/logs"
            if query_string:
                proxy_url += f"?{query_string}"
            
            logger.info(f"🔄 Redirecting logs request to proxy: {proxy_url}")
            return redirect(proxy_url)
    
    # If we can't figure out the device, return an error
    logger.warning(f"❌ Orphaned logs request - no device context found")
    return jsonify({'error': 'No device context found'}), 404

@app.route('/api/devices/<int:device_id>/ping')
@login_required
def ping_device_api(device_id):
    """Test device connectivity via tunnel or direct IP"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    # Priority: Tunnel first, then direct IP
    if device.tunnel_port and device.tunnel_status == 'connected':
        # Test tunnel connection with HTTP request
        try:
            # Try to get hub config, but don't fail if it's missing
            hub = HubConfiguration.query.filter_by(is_active=True).first()
            
            if hub:
                # Use authenticated request with hub key
                response = requests.get(
                    f'http://localhost:{device.tunnel_port}/camera_status', 
                    timeout=5,
                    headers={
                        'X-Hub-ID': 'CyberPhysical Hub',
                        'X-Registration-Key': hub.master_registration_key
                    }
                )
                logger.info(f"Tunnel ping with auth: HTTP {response.status_code}")
            else:
                # Fallback: try basic connectivity test without auth
                logger.warning("No hub found, testing basic tunnel connectivity")
                response = requests.get(f'http://localhost:{device.tunnel_port}/', timeout=5)
                logger.info(f"Tunnel ping without auth: HTTP {response.status_code}")
            
            # Any HTTP response means tunnel is working
            device.connection_status = 'connected'
            device.last_seen = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Tunnel responds (HTTP {response.status_code})',
                'connection_type': 'tunnel',
                'target': f'localhost:{device.tunnel_port}',
                'status': 'Connected via SSH tunnel',
                'http_status': response.status_code
            })
            
        except requests.exceptions.Timeout:
            device.connection_status = 'timeout'
            device.last_seen = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': False,
                'error': 'Tunnel connection timeout (5s)',
                'connection_type': 'tunnel',
                'target': f'localhost:{device.tunnel_port}'
            })
            
        except requests.exceptions.ConnectionError as e:
            device.connection_status = 'disconnected'
            device.last_seen = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': False,
                'error': f'Tunnel connection refused: {str(e)}',
                'connection_type': 'tunnel',
                'target': f'localhost:{device.tunnel_port}'
            })
            
        except Exception as e:
            logger.error(f"Tunnel ping error for device {device_id}: {e}")
            return jsonify({
                'success': False,
                'error': f'Tunnel error: {str(e)}',
                'connection_type': 'tunnel',
                'target': f'localhost:{device.tunnel_port}'
            })
    
    elif device.ip_address:
        # Use direct IP ping (existing logic)
        import subprocess
        import time
        
        try:
            start_time = time.time()
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3000', device.ip_address], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode == 0:
                response_time = round((time.time() - start_time) * 1000, 2)
                
                # Extract ping time from output
                if 'time=' in result.stdout:
                    import re
                    time_match = re.search(r'time=(\d+\.?\d*)', result.stdout)
                    if time_match:
                        response_time = float(time_match.group(1))
                
                device.connection_status = 'connected'
                device.last_seen = datetime.utcnow()
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': f'Response time: {response_time}ms',
                    'connection_type': 'direct_ip',
                    'target': device.ip_address,
                    'status': 'Reachable via network ping'
                })
            else:
                device.connection_status = 'disconnected'
                device.last_seen = datetime.utcnow()
                db.session.commit()
                
                return jsonify({
                    'success': False,
                    'error': 'Device unreachable via ping',
                    'connection_type': 'direct_ip',
                    'target': device.ip_address
                })
                
        except subprocess.TimeoutExpired:
            device.connection_status = 'timeout'
            device.last_seen = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': False,
                'error': 'Ping timeout (5s)',
                'connection_type': 'direct_ip',
                'target': device.ip_address
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Ping error: {str(e)}',
                'connection_type': 'direct_ip',
                'target': device.ip_address
            })
    else:
        return jsonify({
            'success': False,
            'error': 'No connection method available (no tunnel or IP)',
            'connection_type': 'none',
            'target': 'N/A'
        })

@app.route('/api/devices/<int:device_id>/approve', methods=['POST'])
@login_required
def approve_device(device_id):
    """Approve a pending device and allow configuration"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    if device.approval_status != 'pending':
        return jsonify({'success': False, 'error': 'Device is not pending approval'}), 400
    
    try:
        # Get configuration data from request
        data = request.get_json() or {}
        
        # Update device with approval and configuration
        device.approval_status = 'approved'
        device.connection_status = 'connected'  # Move from pending to connected
        
        # Allow admin to set a proper name
        if data.get('device_name'):
            device.device_name = data['device_name'].strip()
        
        # Set other optional fields
        if data.get('device_type'):
            device.device_type = data['device_type'].strip()
        if data.get('model_number'):
            device.model_number = data['model_number'].strip()
        if data.get('description'):
            device.description = data['description'].strip()
        
        device.last_seen = datetime.utcnow()
        
        # Get hub's registration key for the device
        hub = HubConfiguration.query.filter_by(is_active=True).first()
        if hub:
            device.registration_key = hub.master_registration_key
        
        db.session.commit()
        
        # Log the approval event
        approval_event = SecurityEvent(
            device_id=device_id,
            event_type='device_approved',
            event_description=f'Device {device.device_name} approved and configured',
            severity_level='info'
        )
        db.session.add(approval_event)
        db.session.commit()
        
        logger.info(f"Device {device_id} approved: {device.device_name}")
        
        return jsonify({
            'success': True,
            'message': f'Device {device.device_name} approved successfully',
            'device': {
                'device_id': device.device_id,
                'device_name': device.device_name,
                'device_type': device.device_type,
                'approval_status': device.approval_status,
                'connection_status': device.connection_status
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error approving device {device_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/<int:device_id>/reject', methods=['POST'])
@login_required
def reject_device(device_id):
    """Reject a pending device and remove it"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    if device.approval_status != 'pending':
        return jsonify({'success': False, 'error': 'Device is not pending approval'}), 400
    
    try:
        device_name = device.device_name
        
        # Log the rejection event before deleting
        rejection_event = SecurityEvent(
            device_id=None,  # Will be orphaned after device deletion
            event_type='device_rejected',
            event_description=f'Device {device_name} rejected and removed',
            severity_level='warning'
        )
        db.session.add(rejection_event)
        
        # Remove the device completely
        db.session.delete(device)
        db.session.commit()
        
        logger.info(f"Device {device_id} rejected and removed: {device_name}")
        
        return jsonify({
            'success': True,
            'message': f'Device {device_name} rejected and removed'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error rejecting device {device_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
    return render_template('map/index.html', 
                         title='Device Map',
                         devices=map_devices)        

@app.route('/debug/devices')
@login_required
def debug_devices():
    """Debug route to see all devices and their statuses"""
    devices = SecurityDevice.query.filter_by(is_active=True).all()
    
    debug_info = []
    for device in devices:
        debug_info.append({
            'id': device.device_id,
            'name': device.device_name,
            'connection_status': device.connection_status,
            'approval_status': device.approval_status,
            'tunnel_port': device.tunnel_port,
            'tunnel_status': device.tunnel_status,
            'ip_address': device.ip_address,
            'is_active': device.is_active
        })
    
    return {'devices': debug_info, 'count': len(devices)} 

@app.route('/api/devices/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device(device_id):
    """Delete a device completely"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    try:
        device_name = device.device_name
        
        # Log the deletion event before deleting
        deletion_event = SecurityEvent(
            device_id=None,  # Will be orphaned after device deletion
            event_type='device_deleted',
            event_description=f'Device {device_name} deleted by admin',
            severity_level='info'
        )
        db.session.add(deletion_event)
        
        # Delete associated records first (to avoid foreign key issues)
        DeviceLocation.query.filter_by(device_id=device_id).delete()
        DeviceStatus.query.filter_by(device_id=device_id).delete()
        SecurityEvent.query.filter_by(device_id=device_id).delete()
        
        # Delete the device
        db.session.delete(device)
        db.session.commit()
        
        logger.info(f"Device {device_id} deleted: {device_name}")
        
        return jsonify({
            'success': True,
            'message': f'Device {device_name} deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting device {device_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500      

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Customer login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find user
        user = CustomerUser.query.filter_by(username=username, is_active=True).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Login successful
            session['user_id'] = user.user_id
            session['customer_id'] = user.customer_id
            session['username'] = user.username
            session['role'] = user.role
            session['last_activity'] = datetime.utcnow().isoformat()
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create login event
            try:
                login_event = SecurityEvent(
                    customer_id=user.customer_id,
                    event_type='user_login',
                    event_description=f'User {user.username} ({user.role}) logged in',
                    severity_level='info'
                )
                db.session.add(login_event)
                db.session.commit()
                logger.info(f"Login event created for user {user.username}")
            except Exception as e:
                logger.error(f"Error creating login event: {e}")
                db.session.rollback()
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('home'))
        else:
            # Failed login attempt - log it
            try:
                failed_login_event = SecurityEvent(
                    event_type='failed_login',
                    event_description=f'Failed login attempt for username: {username}',
                    severity_level='warning'
                )
                db.session.add(failed_login_event)
                db.session.commit()
                logger.warning(f"Failed login attempt for username: {username}")
            except Exception as e:
                logger.error(f"Error creating failed login event: {e}")
                db.session.rollback()
            
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html', title='Login')

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username', 'User')
    customer_id = session.get('customer_id')
    
    # Create logout event before clearing session
    try:
        logout_event = SecurityEvent(
            customer_id=customer_id,
            event_type='user_logout',
            event_description=f'User {username} logged out',
            severity_level='info'
        )
        db.session.add(logout_event)
        db.session.commit()
        logger.info(f"Logout event created for user {username}")
    except Exception as e:
        logger.error(f"Error creating logout event: {e}")
        db.session.rollback()
    
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    return redirect(url_for('login'))

@app.route('/account/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Get current user
        user = CustomerUser.query.get(session['user_id'])
        
        # Verify current password
        if not check_password_hash(user.password_hash, current_password):
            flash('Current password is incorrect', 'error')
            return render_template('account/change_password.html')
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('account/change_password.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('account/change_password.html')
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('home'))
    
    return render_template('account/change_password.html')

@app.route('/recordings')
@login_required
def recordings():
    """Video recordings management page"""
    # Check if user is logged in as a customer
    if 'customer_id' in session:
        # Customer view - filter by customer_id (for future implementation)
        customer_id = session['customer_id']
        customer = Customer.query.get(customer_id)
        return render_template('recordings/index.html', 
                             title=f'{customer.customer_name} - Video Recordings',
                             customer=customer,
                             is_customer_view=True)
    else:
        # Admin/system view - show all recordings
        return render_template('recordings/index.html', 
                             title='Video Recordings',
                             is_customer_view=False)

@app.route('/api/devices/<int:device_id>/download_videos', methods=['POST'])
@login_required
def download_device_videos(device_id):
    """Download videos from a specific device with customer isolation"""
    device = db.session.get(SecurityDevice, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    # CRITICAL: Strict customer isolation - NO defaults allowed
    if not device.customer_id:
        return jsonify({
            'success': False, 
            'error': 'Device has no customer assignment - cannot download videos'
        }), 403

    customer_id = str(device.customer_id).zfill(3)  # Format as 001, 002, etc.
    
    # Create customer-specific video directory
    import os
    video_dir = f"./videos/customer_{customer_id}/"
    os.makedirs(video_dir, exist_ok=True)
    
    # Create thumbnails directory
    thumbnail_dir = f"./thumbnails/customer_{customer_id}/"
    os.makedirs(thumbnail_dir, exist_ok=True)
    
    # Get list of videos from device
    video_list, error = device_manager.make_device_request(device_id, '/api/videos')
    if error:
        return jsonify({'success': False, 'error': f'Failed to get video list: {error}'}), 500
    
    if not video_list or not isinstance(video_list, list):
        return jsonify({'success': False, 'error': 'No videos found on device'}), 404
    
    # Download each video file AND its thumbnail
    downloaded_count = 0
    for video_info in video_list:
        try:
            video_filename = video_info.get('filename')
            if not video_filename:
                continue
                
            # Download video file from device - handle binary data properly
            import requests
            hub = HubConfiguration.query.filter_by(is_active=True).first()
            if device.tunnel_port and device.tunnel_status == 'connected':
                download_url_base = f"http://localhost:{device.tunnel_port}"
            else:
                download_url_base = f"http://{device.ip_address}:{device.port}"

            # Download video
            video_response = requests.get(f"{download_url_base}/api/download/{video_filename}", headers={
                'X-Hub-ID': 'CyberPhysical Hub',
                'X-Registration-Key': hub.master_registration_key
            }, timeout=30)

            if video_response.status_code != 200:
                logger.error(f"Failed to download {video_filename}: HTTP {video_response.status_code}")
                continue

            # Save video to customer directory
            video_path = os.path.join(video_dir, video_filename)
            with open(video_path, 'wb') as f:
                f.write(video_response.content)
            
            # Download corresponding thumbnail
            thumbnail_filename = video_filename.replace('.ogv', '.jpg').replace('.webm', '.jpg').replace('.mp4', '.jpg')
            try:
                thumbnail_response = requests.get(f"{download_url_base}/thumbnails/{thumbnail_filename}", headers={
                    'X-Hub-ID': 'CyberPhysical Hub',
                    'X-Registration-Key': hub.master_registration_key
                }, timeout=10)
                
                if thumbnail_response.status_code == 200:
                    thumbnail_path = os.path.join(thumbnail_dir, thumbnail_filename)
                    with open(thumbnail_path, 'wb') as f:
                        f.write(thumbnail_response.content)
                    logger.info(f"Downloaded thumbnail: {thumbnail_filename}")
                else:
                    logger.warning(f"Thumbnail not available for {video_filename}")
                    
            except Exception as thumb_error:
                logger.warning(f"Failed to download thumbnail for {video_filename}: {thumb_error}")
            
            downloaded_count += 1
            logger.info(f"Downloaded video: {video_path}")
            
        except Exception as e:
            logger.error(f"Error downloading video {video_filename}: {e}")
            continue
    
    return jsonify({
        'success': True, 
        'message': f'Downloaded {downloaded_count} videos from device {device.device_name}',
        'storage_path': video_dir,
        'downloaded_count': downloaded_count,
        'total_videos': len(video_list)
    })

@app.route('/thumbnails/<path:filename>')
@login_required
def serve_thumbnail(filename):
    import os
    """Serve thumbnail images with customer isolation"""
    try:
        if ".." in filename or filename.startswith("/"):
            return "Invalid filename", 400
        
        # Check if user is logged in as a customer
        if 'customer_id' in session:
            customer_id = str(session['customer_id']).zfill(3)
        else:
            customer_id = '001'  # Default for admin view
        
        thumbnail_dir = f"./thumbnails/customer_{customer_id}/"
        
        # Check if directory exists
        if not os.path.exists(thumbnail_dir):
            logger.error(f"Thumbnail directory does not exist: {thumbnail_dir}")
            return "Thumbnail directory not found", 404
        
        thumbnail_path = os.path.join(thumbnail_dir, filename)
        if not os.path.exists(thumbnail_path):
            logger.error(f"Thumbnail file not found: {thumbnail_path}")
            return "Thumbnail not found", 404
            
        return send_from_directory(thumbnail_dir, filename)
        
    except Exception as e:
        logger.error(f"Error serving thumbnail {filename}: {e}")
        return f"Error serving thumbnail: {str(e)}", 500

@app.route('/api/recordings')
@login_required
def list_recordings():
    import os
    """Get downloaded videos with customer isolation"""
    # Check if user is logged in as a customer
    if 'customer_id' in session:
        customer_id = str(session['customer_id']).zfill(3)
    else:
        customer_id = '001'  # Default for admin view
    
    video_dir = f"./videos/customer_{customer_id}/"
    videos = []
    
    if os.path.exists(video_dir):
        for filename in os.listdir(video_dir):
            if filename.endswith('.ogv'):
                filepath = os.path.join(video_dir, filename)
                stat = os.stat(filepath)
                videos.append({
                    'filename': filename,
                    'size': round(stat.st_size / (1024*1024), 2),  # MB
                    'date': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
    
    # Sort by date, newest first
    videos.sort(key=lambda x: x['date'], reverse=True)
    return jsonify(videos)

@app.route('/api/recordings/download/<filename>')
@login_required
def download_recording(filename):
    """Download a specific recording with customer isolation"""
    # Check if user is logged in as a customer
    if 'customer_id' in session:
        customer_id = str(session['customer_id']).zfill(3)
    else:
        customer_id = '001'  # Default for admin view
    
    video_dir = f"./videos/customer_{customer_id}/"
    
    # Security check - prevent directory traversal
    if ".." in filename or filename.startswith("/"):
        return "Invalid filename", 400
    
    return send_from_directory(video_dir, filename, as_attachment=True)

@app.route('/api/recordings/download/<filename>')
@login_required
def download_hub_recording(filename):
    """Download a specific recording with customer isolation"""
    # Check if user is logged in as a customer
    if 'customer_id' in session:
        customer_id = str(session['customer_id']).zfill(3)
    else:
        customer_id = '001'  # Default for admin view
    
    video_dir = f"./videos/customer_{customer_id}/"
    
    # Security check - prevent directory traversal
    if ".." in filename or filename.startswith("/"):
        return "Invalid filename", 400
    
    return send_from_directory(video_dir, filename, as_attachment=True)


@app.route('/api/update/check', methods=['GET'])
@login_required
def check_for_updates():
    """Check if updates are available on GitHub"""
    try:
        # Get current commit hash
        current_commit = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                      capture_output=True, text=True, cwd='.')
        if current_commit.returncode != 0:
            return jsonify({'success': False, 'error': 'Not a git repository'})
        
        current_hash = current_commit.stdout.strip()
        
        # Fetch latest from origin without merging
        fetch_result = subprocess.run(['git', 'fetch', 'origin'], 
                                    capture_output=True, text=True, cwd='.')
        if fetch_result.returncode != 0:
            return jsonify({'success': False, 'error': 'Failed to fetch from GitHub'})
        
        # Get remote commit hash
        remote_commit = subprocess.run(['git', 'rev-parse', 'origin/main'], 
                                     capture_output=True, text=True, cwd='.')
        if remote_commit.returncode != 0:
            # Try 'master' branch if 'main' doesn't exist
            remote_commit = subprocess.run(['git', 'rev-parse', 'origin/master'], 
                                         capture_output=True, text=True, cwd='.')
        
        if remote_commit.returncode != 0:
            return jsonify({'success': False, 'error': 'Could not get remote commit hash'})
        
        remote_hash = remote_commit.stdout.strip()
        
        # Check if update is available
        update_available = current_hash != remote_hash
        
        # Get commit messages for changes
        changes = []
        if update_available:
            log_result = subprocess.run([
                'git', 'log', f'{current_hash}..{remote_hash}', 
                '--oneline', '--max-count=10'
            ], capture_output=True, text=True, cwd='.')
            
            if log_result.returncode == 0:
                changes = log_result.stdout.strip().split('\n')
                changes = [line for line in changes if line.strip()]
        
        return jsonify({
            'success': True,
            'update_available': update_available,
            'current_commit': current_hash[:8],
            'remote_commit': remote_hash[:8],
            'changes': changes,
            'last_check': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update/perform', methods=['POST'])
@login_required
def perform_update():
    """Perform the update by pulling from GitHub"""
    try:
        # Check if we're in a clean state
        status_result = subprocess.run(['git', 'status', '--porcelain'], 
                                     capture_output=True, text=True, cwd='.')
        
        if status_result.stdout.strip():
            return jsonify({
                'success': False, 
                'error': 'Working directory has uncommitted changes. Update aborted.'
            })
        
        # Store current commit for rollback
        current_commit = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                      capture_output=True, text=True, cwd='.')
        rollback_hash = current_commit.stdout.strip()
        
        # Pull the latest changes
        pull_result = subprocess.run(['git', 'pull', 'origin'], 
                                   capture_output=True, text=True, cwd='.')
        
        if pull_result.returncode != 0:
            return jsonify({
                'success': False, 
                'error': f'Git pull failed: {pull_result.stderr}'
            })
        
        # Check if any Python dependencies need updating
        requirements_changed = 'requirements.txt' in pull_result.stdout
        
        update_info = {
            'success': True,
            'message': 'Update completed successfully',
            'changes_pulled': pull_result.stdout,
            'requirements_updated': requirements_changed,
            'rollback_commit': rollback_hash[:8],
            'restart_required': True
        }
        
        # If requirements changed, try to update them
        if requirements_changed and os.path.exists('requirements.txt'):
            pip_result = subprocess.run([
                'pip', 'install', '-r', 'requirements.txt'
            ], capture_output=True, text=True)
            
            update_info['pip_update'] = {
                'success': pip_result.returncode == 0,
                'output': pip_result.stdout if pip_result.returncode == 0 else pip_result.stderr
            }
        
        # Schedule restart in 5 seconds to allow response to be sent
        def restart_server():
            import time
            time.sleep(5)
            os.system('sudo systemctl restart cpHub')  # Adjust service name as needed
        
        restart_thread = threading.Thread(target=restart_server, daemon=True)
        restart_thread.start()
        
        return jsonify(update_info)
        
    except Exception as e:
        logger.error(f"Error performing update: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update/rollback', methods=['POST'])
@login_required
def rollback_update():
    """Rollback to previous commit"""
    try:
        rollback_commit = request.json.get('commit_hash')
        if not rollback_commit:
            return jsonify({'success': False, 'error': 'No commit hash provided'})
        
        # Reset to previous commit
        reset_result = subprocess.run(['git', 'reset', '--hard', rollback_commit], 
                                    capture_output=True, text=True, cwd='.')
        
        if reset_result.returncode != 0:
            return jsonify({
                'success': False, 
                'error': f'Rollback failed: {reset_result.stderr}'
            })
        
        return jsonify({
            'success': True,
            'message': f'Rolled back to commit {rollback_commit[:8]}',
            'restart_required': True
        })
        
    except Exception as e:
        logger.error(f"Error rolling back update: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update/status')
@login_required
def update_status():
    """Get current git status and update information"""
    try:
        # Get current branch
        branch_result = subprocess.run(['git', 'branch', '--show-current'], 
                                     capture_output=True, text=True, cwd='.')
        current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else 'unknown'
        
        # Get current commit
        commit_result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                     capture_output=True, text=True, cwd='.')
        current_commit = commit_result.stdout.strip()[:8] if commit_result.returncode == 0 else 'unknown'
        
        # Get last commit message
        message_result = subprocess.run(['git', 'log', '-1', '--pretty=%B'], 
                                      capture_output=True, text=True, cwd='.')
        last_message = message_result.stdout.strip() if message_result.returncode == 0 else 'No commit message'
        
        # Get remote URL
        remote_result = subprocess.run(['git', 'remote', 'get-url', 'origin'], 
                                     capture_output=True, text=True, cwd='.')
        remote_url = remote_result.stdout.strip() if remote_result.returncode == 0 else 'No remote'
        
        return jsonify({
            'success': True,
            'current_branch': current_branch,
            'current_commit': current_commit,
            'last_commit_message': last_message,
            'remote_url': remote_url,
            'git_available': True
        })
        
    except Exception as e:
        logger.error(f"Error getting update status: {e}")
        return jsonify({'success': False, 'error': str(e), 'git_available': False})

@app.route('/admin/users')
@login_required
def manage_users():
    """User management page - admin only"""
    # Check if user is admin
    if session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    # Get current customer_id if customer user
    customer_id = session.get('customer_id')
    
    # Get all users for this customer
    if customer_id:
        users = CustomerUser.query.filter_by(customer_id=customer_id).all()
        customer = Customer.query.get(customer_id)
    else:
        users = CustomerUser.query.all()
        customer = None
    
    return render_template('admin/users.html', 
                         title='User Management',
                         users=users,
                         customer=customer)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    """Add new user - admin only"""
    # Check if user is admin
    if session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            email = request.form.get('email', '').strip()
            role = request.form.get('role', 'viewer')
            
            # Get customer_id from session (for customer admins)
            customer_id = session.get('customer_id')
            
            # Validate input
            if not username or not password:
                flash('Username and password are required', 'error')
                return redirect(url_for('add_user'))
            
            # Check if username already exists
            existing_user = CustomerUser.query.filter_by(username=username).first()
            if existing_user:
                flash(f'Username "{username}" already exists', 'error')
                return redirect(url_for('add_user'))
            
            # Create new user
            new_user = create_customer_user(
                customer_id=customer_id,
                username=username,
                password=password,
                email=email,
                role=role
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Create user creation event
            try:
                creation_event = SecurityEvent(
                    customer_id=customer_id,
                    event_type='user_created',
                    event_description=f'User {username} ({role}) created by {session.get("username")}',
                    severity_level='info'
                )
                db.session.add(creation_event)
                db.session.commit()
                logger.info(f"User creation event logged for {username}")
            except Exception as e:
                logger.error(f"Error creating user creation event: {e}")
                db.session.rollback()
            
            flash(f'User "{username}" created successfully!', 'success')
            return redirect(url_for('manage_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
            return redirect(url_for('add_user'))
    
    # GET request - show form
    customer_id = session.get('customer_id')
    customer = Customer.query.get(customer_id) if customer_id else None
    
    return render_template('admin/add_user.html', 
                         title='Add New User',
                         customer=customer)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user - admin only"""
    # Check if user is admin
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        user = CustomerUser.query.get_or_404(user_id)
        
        # Prevent deleting yourself
        if user.user_id == session.get('user_id'):
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
        
        # Check if user belongs to same customer (for customer admins)
        customer_id = session.get('customer_id')
        if customer_id and user.customer_id != customer_id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        username = user.username
        user_role = user.role
        user_customer_id = user.customer_id
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        # Create user deletion event
        try:
            deletion_event = SecurityEvent(
                customer_id=user_customer_id,
                event_type='user_deleted',
                event_description=f'User {username} ({user_role}) deleted by {session.get("username")}',
                severity_level='warning'
            )
            db.session.add(deletion_event)
            db.session.commit()
            logger.info(f"User deletion event logged for {username}")
        except Exception as e:
            logger.error(f"Error creating user deletion event: {e}")
            db.session.rollback()
        
        return jsonify({
            'success': True,
            'message': f'User "{username}" deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

#CP App API Routes
@app.route('/api/mobile/devices', methods=['GET'])
def mobile_api_devices():
    try:
        devices = SecurityDevice.query.all()
        devices_data = []
        
        for device in devices:
            # Use the same logic as your web interface for determining connection status
            if device.connection_status == 'connected' or device.tunnel_status == 'connected':
                actual_status = 'connected'
            elif device.connection_status in ['pending', 'tunnel_pending']:
                actual_status = 'pending'
            else:
                actual_status = 'disconnected'
            
            device_info = {
                'id': device.device_id,
                'name': device.device_name,
                'ip_address': device.ip_address,
                'device_type': device.device_type,
                'status': actual_status,  # Use the calculated status
                'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                'is_approved': device.approval_status == 'approved'
            }
            devices_data.append(device_info)
        
        return jsonify({
            'success': True,
            'devices': devices_data,
            'count': len(devices_data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/mobile/cameras', methods=['GET'])
def mobile_api_cameras():
    try:
        devices = SecurityDevice.query.filter_by(is_active=True).all()
        cameras_data = []
        
        for device in devices:
            # Check if device is connected
            if device.connection_status == 'connected' or device.tunnel_status == 'connected':
                status = 'online'
            else:
                status = 'offline'
            
            # Add both Camera A and Camera B for each device
            cameras_data.append({
                'device_id': device.device_id,
                'device_name': device.device_name,
                'camera_id': 'A',
                'camera_name': f'{device.device_name} - Camera A',
                'status': status,
                'stream_url': f'/proxy/{device.device_id}/live/camera1' if device.tunnel_port else f'http://{device.ip_address}:{device.port}/live/camera1'
            })
            
            cameras_data.append({
                'device_id': device.device_id,
                'device_name': device.device_name,
                'camera_id': 'B',
                'camera_name': f'{device.device_name} - Camera B',
                'status': status,
                'stream_url': f'/proxy/{device.device_id}/live/camera2' if device.tunnel_port else f'http://{device.ip_address}:{device.port}/live/camera2'
            })
        
        return jsonify({
            'success': True,
            'cameras': cameras_data,
            'count': len(cameras_data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# 3) Video recordings
@app.route('/api/mobile/recordings', methods=['GET'])
def mobile_api_recordings():
    import os
    try:
        # For mobile, we'll default to customer 001 or make it configurable later
        customer_id = '001'  # You can make this dynamic later
        video_dir = f"./videos/customer_{customer_id}/"
        recordings = []
        
        if os.path.exists(video_dir):
            for filename in os.listdir(video_dir):
                if filename.endswith('.ogv'):
                    filepath = os.path.join(video_dir, filename)
                    stat = os.stat(filepath)
                    
                    # Extract info from filename if possible
                    camera_id = 'A' if '_A_' in filename or 'CameraA' in filename else 'B'
                    
                    recordings.append({
                        'id': filename,
                        'filename': filename,
                        'camera_id': camera_id,
                        'size_mb': round(stat.st_size / (1024*1024), 2),
                        'date': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'download_url': f'/api/recordings/download/{filename}',
                        'thumbnail_url': f'/thumbnails/{filename.replace(".ogv", ".jpg")}'
                    })
        
        # Sort by date, newest first
        recordings.sort(key=lambda x: x['date'], reverse=True)
        
        return jsonify({
            'success': True,
            'recordings': recordings,
            'count': len(recordings)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# 4) Security events
@app.route('/api/mobile/events', methods=['GET'])
def mobile_api_events():
    try:
        # Get recent events (limit to last 50 for mobile)
        events = SecurityEvent.query.order_by(SecurityEvent.event_timestamp.desc()).limit(50).all()
        events_data = []
        
        for event in events:
            events_data.append({
                'id': event.event_id,
                'type': event.event_type,
                'device_id': event.device_id,
                'device_name': event.device.device_name if event.device else 'Unknown',
                'description': event.event_description,
                'severity': event.severity_level,
                'timestamp': event.event_timestamp.isoformat(),
                'is_resolved': event.is_resolved,
                'resolution_notes': event.resolution_notes
            })
        
        return jsonify({
            'success': True,
            'events': events_data,
            'count': len(events_data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500   

@app.route('/api/devices/<int:device_id>/recording_status')
def get_device_recording_status(device_id):
    """Check if any cameras on this device are currently recording due to motion detection"""
    try:
        device = db.session.get(SecurityDevice, device_id)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        
        print(f"=== DEBUG: Starting recording status check for device {device_id} ===")
        
        # Use device manager to get camera status from the actual device
        camera_data, camera_error = device_manager.make_device_request(device_id, '/camera_status')
        
        print(f"Device manager result: data={camera_data}, error={camera_error}")
        
        if camera_error:
            return jsonify({
                'success': False, 
                'error': camera_error,
                'is_recording': False
            })
        
        print(f"Camera data received: {camera_data}")
        
        # Check if any cameras are actively recording
        is_recording = False
        recording_cameras = []
        
        if camera_data:
            print(f"Checking Camera_1: '{camera_data.get('Camera_1')}'")
            print(f"Checking Camera_2: '{camera_data.get('Camera_2')}'")
            
            # Check for Camera_1 recording - fix the key name
            camera1_status = camera_data.get('Camera_1') or camera_data.get('Camera 1')
            if camera1_status == 'Recording':
                is_recording = True
                recording_cameras.append('Camera_1')
                print(f"✅ Camera_1 is recording!")
            
            # Check for Camera_2 recording - fix the key name  
            camera2_status = camera_data.get('Camera_2') or camera_data.get('Camera 2')
            if camera2_status == 'Recording':
                is_recording = True
                recording_cameras.append('Camera_2')
                print(f"✅ Camera_2 is recording!")
        
        print(f"Final result: is_recording={is_recording}, cameras={recording_cameras}")

        if camera_data:
            print(f"=== ALL CAMERA DATA KEYS ===")
            for key, value in camera_data.items():
                print(f"Key: '{key}' = Value: '{value}'")
            print(f"=== END CAMERA DATA ===")
        
        return jsonify({
            'success': True,
            'is_recording': is_recording,
            'recording_cameras': recording_cameras,
            'camera_data': camera_data
        })
        
    except Exception as e:
        print(f"Exception in recording status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'error': str(e),
            'is_recording': False
        }), 500

def setup_ssl_context():
    """Setup SSL context for HTTPS"""
    ssl_dir = "ssl"
    cert_file = os.path.join(ssl_dir, "hub_cert.pem")
    key_file = os.path.join(ssl_dir, "hub_key.pem")
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.error("❌ SSL certificates not found!")
        logger.error(f"Expected files: {cert_file}, {key_file}")
        logger.error("Run: python generate_ssl_cert.py")
        return None
    
    try:
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        
        # Security settings
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        logger.info(f"✅ SSL context loaded successfully")
        logger.info(f"📄 Certificate: {cert_file}")
        logger.info(f"🔑 Private Key: {key_file}")
        
        return context
        
    except Exception as e:
        logger.error(f"❌ Error setting up SSL context: {e}")
        return None

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=7700, debug=False)
