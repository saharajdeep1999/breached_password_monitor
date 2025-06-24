from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from datetime import datetime

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
    import yaml
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    db_path = config['database']['path']
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)
