import logging
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime
import threading
import queue
import time

class AdvancedWAFLogger:
    def __init__(self, config=None):
        self.config = config or self._default_config()
        
        # Setup structured logging
        self.logger = self._setup_logger()
        
        # Alert queue for async processing
        self.alert_queue = queue.Queue()
        
        # Start alert processing thread
        self.alert_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.alert_thread.start()
        
        # Statistics tracking
        self.alert_stats = {
            'total_alerts': 0,
            'email_alerts': 0,
            'slack_alerts': 0,
            'webhook_alerts': 0,
            'failed_alerts': 0
        }

    def _default_config(self):
        """Default logging and alerting configuration"""
        return {
            'log_level': 'INFO',
            'log_file': 'waf.log',
            'max_log_size': 100 * 1024 * 1024,  # 100MB
            'backup_count': 5,
            'email_alerts': {
                'enabled': True,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': 'mlbasedwafproject@gmail.com',
                'password': 'xzfo tgrc qhkz zato',
                'recipients': ['admin@company.com'],
                'severity_threshold': 'HIGH'
            },
            'slack_alerts': {
                'enabled': False,
                'webhook_url': 'https://hooks.slack.com/services/...',
                'channel': '#security-alerts',
                'severity_threshold': 'MEDIUM'
            },
            'webhook_alerts': {
                'enabled': False,
                'endpoints': [],
                'timeout': 30
            }
        }

    def _setup_logger(self):
        """Setup structured logging with rotation"""
        from logging.handlers import RotatingFileHandler
        
        logger = logging.getLogger('waf_logger')
        logger.setLevel(getattr(logging, self.config['log_level']))
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            self.config['log_file'],
            maxBytes=self.config['max_log_size'],
            backupCount=self.config['backup_count']
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        
        # JSON formatter for structured logging
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"component": "%(name)s", "message": %(message)s}'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def log_request(self, request_data, classification_result, action_taken):
        """Log HTTP request with classification result"""
        log_entry = {
            'event_type': 'http_request',
            'timestamp': datetime.now().isoformat(),
            'client_ip': request_data.get('client_ip', 'unknown'),
            'method': request_data.get('method', 'unknown'),
            'url': request_data.get('url', ''),
            'user_agent': request_data.get('headers', {}).get('User-Agent', ''),
            'classification': {
                'is_malicious': classification_result.get('is_malicious', False),
                'confidence': classification_result.get('confidence', 0.0),
                'threat_score': classification_result.get('threat_score', 0.0)
            },
            'action_taken': action_taken,
            'features': classification_result.get('features', {})
        }
        
        # Log to file
        self.logger.info(json.dumps(log_entry))
        
        # Generate alert if malicious
        if classification_result.get('is_malicious', False):
            self._generate_alert(log_entry)

    def log_system_event(self, event_type, details, severity='INFO'):
        """Log system events (startup, shutdown, errors, etc.)"""
        log_entry = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'details': details
        }
        
        self.logger.log(getattr(logging, severity), json.dumps(log_entry))
        
        # Generate alert for high-severity events
        if severity in ['ERROR', 'CRITICAL']:
            self._generate_alert(log_entry, alert_type='system_event')

    def log_model_update(self, update_details):
        """Log model retraining and updates"""
        log_entry = {
            'event_type': 'model_update',
            'timestamp': datetime.now().isoformat(),
            'old_accuracy': update_details.get('old_accuracy', 0.0),
            'new_accuracy': update_details.get('new_accuracy', 0.0),
            'improvement': update_details.get('improvement', 0.0),
            'samples_used': update_details.get('samples_used', 0),
            'update_successful': update_details.get('success', False)
        }
        
        self.logger.info(json.dumps(log_entry))

    def _generate_alert(self, log_entry, alert_type='security_threat'):
        """Generate alert based on log entry"""
        severity = self._determine_alert_severity(log_entry)
        
        alert = {
            'type': alert_type,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'data': log_entry
        }
        
        # Add to alert queue for async processing
        self.alert_queue.put(alert)

    def _determine_alert_severity(self, log_entry):
        """Determine alert severity based on threat characteristics"""
        if log_entry.get('event_type') == 'system_event':
            return log_entry.get('severity', 'INFO')
        
        classification = log_entry.get('classification', {})
        confidence = classification.get('confidence', 0.0)
        
        if confidence >= 0.95:
            return 'CRITICAL'
        elif confidence >= 0.85:
            return 'HIGH'
        elif confidence >= 0.70:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _process_alerts(self):
        """Process alerts from queue asynchronously"""
        while True:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._send_alert(alert)
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f'"alert_processing_error": "{str(e)}"')

    def _send_alert(self, alert):
        """Send alert via configured channels"""
        self.alert_stats['total_alerts'] += 1
        severity = alert['severity']
        
        try:
            # Email alerts
            if (self.config['email_alerts']['enabled'] and 
                self._should_send_alert(severity, self.config['email_alerts']['severity_threshold'])):
                self._send_email_alert(alert)
            
            # Slack alerts
            if (self.config['slack_alerts']['enabled'] and 
                self._should_send_alert(severity, self.config['slack_alerts']['severity_threshold'])):
                self._send_slack_alert(alert)
            
            # Webhook alerts
            if self.config['webhook_alerts']['enabled']:
                self._send_webhook_alerts(alert)
                
        except Exception as e:
            self.alert_stats['failed_alerts'] += 1
            self.logger.error(f'"alert_send_error": "{str(e)}"')

    def _should_send_alert(self, alert_severity, threshold):
        """Check if alert should be sent based on severity threshold"""
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        return severity_levels.get(alert_severity, 0) >= severity_levels.get(threshold, 0)

    def _send_email_alert(self, alert):
        """Send email alert"""
        try:
            config = self.config['email_alerts']
            
            msg = MIMEMultipart()
            msg['From'] = config['username']
            msg['To'] = ', '.join(config['recipients'])
            msg['Subject'] = f"WAF Alert - {alert['severity']} Threat Detected"
            
            # Create email body
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
            server.starttls()
            server.login(config['username'], config['password'])
            server.send_message(msg)
            server.quit()
            
            self.alert_stats['email_alerts'] += 1
            
        except Exception as e:
            raise Exception(f"Email alert failed: {str(e)}")

    def _format_email_body(self, alert):
        """Format email alert body"""
        data = alert['data']
        classification = data.get('classification', {})
        
        return f"""
        <html>
        <body>
            <h2>WAF Security Alert</h2>
            <p><strong>Severity:</strong> {alert['severity']}</p>
            <p><strong>Time:</strong> {alert['timestamp']}</p>
            <p><strong>Client IP:</strong> {data.get('client_ip', 'Unknown')}</p>
            <p><strong>URL:</strong> {data.get('url', 'Unknown')}</p>
            <p><strong>Method:</strong> {data.get('method', 'Unknown')}</p>
            <p><strong>Threat Confidence:</strong> {classification.get('confidence', 0)*100:.1f}%</p>
            <p><strong>Action Taken:</strong> {data.get('action_taken', 'Unknown')}</p>
            
            <h3>Request Details:</h3>
            <pre>{json.dumps(data, indent=2)}</pre>
        </body>
        </html>
        """

    def _send_slack_alert(self, alert):
        """Send Slack alert"""
        try:
            config = self.config['slack_alerts']
            data = alert['data']
            classification = data.get('classification', {})
            
            # Format Slack message
            slack_data = {
                'channel': config['channel'],
                'username': 'WAF-Bot',
                'icon_emoji': ':warning:',
                'attachments': [{
                    'color': self._get_alert_color(alert['severity']),
                    'title': f"{alert['severity']} Threat Detected",
                    'fields': [
                        {
                            'title': 'Client IP',
                            'value': data.get('client_ip', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Confidence',
                            'value': f"{classification.get('confidence', 0)*100:.1f}%",
                            'short': True
                        },
                        {
                            'title': 'URL',
                            'value': data.get('url', 'Unknown')[:100] + ('...' if len(data.get('url', '')) > 100 else ''),
                            'short': False
                        },
                        {
                            'title': 'Action',
                            'value': data.get('action_taken', 'Unknown'),
                            'short': True
                        }
                    ],
                    'timestamp': int(time.time())
                }]
            }
            
            response = requests.post(
                config['webhook_url'],
                json=slack_data,
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"Slack API returned status {response.status_code}")
            
            self.alert_stats['slack_alerts'] += 1
            
        except Exception as e:
            raise Exception(f"Slack alert failed: {str(e)}")

    def _get_alert_color(self, severity):
        """Get color for alert based on severity"""
        colors = {
            'LOW': '#36a64f',      # Green
            'MEDIUM': '#ffaa00',   # Orange  
            'HIGH': '#ff6b6b',     # Red
            'CRITICAL': '#8b0000'  # Dark red
        }
        return colors.get(severity, '#cccccc')

    def _send_webhook_alerts(self, alert):
        """Send webhook alerts to configured endpoints"""
        try:
            config = self.config['webhook_alerts']
            
            for endpoint in config['endpoints']:
                response = requests.post(
                    endpoint,
                    json=alert,
                    timeout=config['timeout']
                )
                
                if response.status_code not in [200, 201, 202]:
                    self.logger.warning(f'"webhook_error": "Endpoint {endpoint} returned {response.status_code}"')
                else:
                    self.alert_stats['webhook_alerts'] += 1
                    
        except Exception as e:
            raise Exception(f"Webhook alert failed: {str(e)}")

    def get_alert_stats(self):
        """Get alerting statistics"""
        return self.alert_stats

    def export_logs(self, start_time=None, end_time=None, output_file=None):
        """Export logs for analysis or compliance"""
        # Implementation for log export functionality
        pass
