from src.monitor import monitoring_job
import yaml
from apscheduler.schedulers.blocking import BlockingScheduler
from datetime import datetime

def load_config():
    with open("config/config.yaml") as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    config = load_config()
    scheduler = BlockingScheduler()
    
    scheduler.add_job(
        monitoring_job,
        'interval',
        hours=config['monitoring']['check_interval_hours']
    )
    
    print("Breached Password Monitor started. Press Ctrl+C to exit.")
    try:
        scheduler.start()
    except KeyboardInterrupt:
        print("\nMonitor stopped")
