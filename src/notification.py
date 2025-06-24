import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import requests
from datetime import datetime

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
            html += f"""
            <li>
                <strong>{breach['alias'] or 'Password #'+str(breach['id'])}</strong><br>
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
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{breach['alias'] or 'Password #'+str(breach['id'])}*\n"
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
        except Exception as e:
            print(f"Slack notification failed: {e}")
