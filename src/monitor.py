import yaml
from apscheduler.schedulers.blocking import BlockingScheduler
from datetime import datetime
import requests
import hashlib
import time
from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import os

# Database setup
Base = declarative_base()

class MonitoredPassword(Base):
    __tablename__ = 'monitored_passwords'
    
    id = Column(Integer, primary_key=True)
    sha1_prefix = Column(String(5), nullable=False)
    sha1_suffix = Column(String(35), nullable=False)
    alias = Column(String(50), nullable=True)
    first_detected = Column(DateTime, default=datetime.now)
    last_checked = Column(DateTime, onupdate=datetime.now)
    breach_count = Column(Integer, default=0)
    is_active = Column(Integer, default=1)

def init_db(config_path="config/config.yaml"):
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    db_path = config['database']['path']
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return scoped_session(sessionmaker(bind=engine))

# HIBP Client
class HIBPClient:
    def __init__(self, config):
        self.api_url = config['hibp']['api_url']
        self.rate_limit = config['hibp']['rate_limit']
    
    def check_password(self, password):
        """Check a single password against HIBP"""
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        return self.check_hash(prefix, suffix)
    
    def check_hash(self, prefix, suffix):
        """Check password hash against HIBP"""
        try:
            response = requests.get(
                f"{self.api_url}{prefix}",
                headers={'User-Agent': 'BreachedPasswordMonitor/1.0'},
                timeout=5
            )
            response.raise_for_status()
            
            for line in response.text.splitlines():
                parts = line.split(':')
                if len(parts) == 2:
                    hash_suffix, count = parts
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except Exception as e:
            print(f"HIBP API error: {e}")
            return -1
        finally:
            time.sleep(self.rate_limit)
    
    def batch_check(self, session):
        """Check all monitored passwords"""
        results = []
        passwords = session.query(MonitoredPassword).filter_by(is_active=1).all()
        
        for pwd in passwords:
            count = self.check_hash(pwd.sha1_prefix, pwd.sha1_suffix)
            if count == -1:  # API error
                continue
                
            if count > pwd.breach_count:
                results.append({
                    "id": pwd.id,
                    "alias": pwd.alias,
                    "previous_count": pwd.breach_count,
                    "new_count": count,
                    "breached": count > 0
                })
                pwd.breach_count = count
                pwd.last_checked = datetime.now()
        
        session.commit()
        return results

# Notification Manager
class NotificationManager:
    def __init__(self, config):
        self.config = config['notifications']
    
    def send_breach_alert(self, breaches):
        if not breaches:
            return
        
        # Email notification
        if self.config['email']['enabled']:
            self._send_email(breaches)
        
        # Slack notification
        if self.config['slack']['enabled']:
            self._send_slack(breaches)
    
    def _send_email(self, breaches):
        msg = MIMEMultipart()
        msg['Subject'] = f"Password Breach Alert - {datetime.now().strftime('%Y-%m-%d')}"
        msg['From'] = self.config['email']['from_addr']
        msg['To'] = ", ".join(self.config['email']['to_addrs'])
        
        # Create HTML content
        html = """<h1>Password Breach Alert</h1>
        <p>The following monitored passwords have been compromised:</p>
        <ul>"""
        
        for breach in breaches:
            alias = breach['alias'] or f"Password #{breach['id']}"
            html += f"""
            <li>
                <strong>{alias}</strong><br>
                Previous breaches: {breach['previous_count']}<br>
                New breach count: <span style="color:red">{breach['new_count']}</span>
            </li>"""
        
        html += "</ul><p>Immediately rotate affected credentials.</p>"
        
        msg.attach(MIMEText(html, 'html'))
        
        try:
            with smtplib.SMTP(
                self.config['email']['smtp_server'],
                self.config['email']['smtp_port']
            ) as server:
                server.starttls()
                server.login(
                    self.config['email']['username'],
                    self.config['email']['password']
                )
                server.send_message(msg)
                print("Breach notification email sent successfully")
        except Exception as e:
            print(f"Email sending failed: {e}")
    
    def _send_slack(self, breaches):
        blocks = [{
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Password Breach Alert"
            }
        }]
        
        for breach in breaches:
            alias = breach['alias'] or f"Password #{breach['id']}"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{alias}*\n"
                        f"Previous breaches: {breach['previous_count']}\n"
                        f"New breach count: {breach['new_count']}"
                    )
                }
            })
        
        try:
            response = requests.post(
                self.config['slack']['webhook_url'],
                json={"blocks": blocks},
                timeout=5
            )
            response.raise_for_status()
            print("Breach notification sent to Slack")
        except Exception as e:
            print(f"Slack notification failed: {e}")

# Monitoring job
def monitoring_job():
    print(f"\n[{datetime.now()}] Starting breach monitoring...")
    config = load_config()
    Session = init_db()
    session = Session()
    
    hibp = HIBPClient(config)
    notifier = NotificationManager(config)
    
    results = hibp.batch_check(session)
    new_breaches = [r for r in results if r['new_count'] > r['previous_count']]
    
    if new_breaches:
        print(f"Detected {len(new_breaches)} new breaches!")
        notifier.send_breach_alert(new_breaches)
    else:
        print("No new breaches detected")
    
    session.close()
    print(f"[{datetime.now()}] Monitoring completed")

def load_config(config_path="config/config.yaml"):
    with open(config_path) as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    print("Initializing Breached Password Monitor...")
    config = load_config()
    
    # Initialize database
    Session = init_db()
    session = Session()
    session.close()
    
    scheduler = BlockingScheduler()
    scheduler.add_job(
        monitoring_job,
        'interval',
        hours=config['monitoring']['check_interval_hours']
    )
    
    # Run immediately on startup
    monitoring_job()
    
    print("Breached Password Monitor started. Press Ctrl+C to exit.")
    try:
        scheduler.start()
    except KeyboardInterrupt:
        print("\nMonitor stopped")
    except Exception as e:
        print(f"Unexpected error: {e}")
