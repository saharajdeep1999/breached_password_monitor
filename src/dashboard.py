from flask import Flask, render_template
import sqlite3
import os
from datetime import datetime, timedelta

app = Flask(__name__)

def get_breach_data():
    conn = sqlite3.connect('data/passwords.db')
    cursor = conn.cursor()
    
    # Get summary stats
    cursor.execute("""
        SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN breach_count > 0 THEN 1 ELSE 0 END) AS breached,
            SUM(breach_count) AS total_breaches
        FROM monitored_passwords
        WHERE is_active = 1
    """)
    stats = cursor.fetchone()
    
    # Get breach history
    history = []
    for i in range(30):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT COUNT(*) 
            FROM breach_history 
            WHERE date(detected_date) = ? 
            AND status = 'new'
        """, (date,))
        count = cursor.fetchone()[0] or 0
        history.append({'date': date, 'count': count})
    
    # Get top breached passwords
    cursor.execute("""
        SELECT alias, breach_count 
        FROM monitored_passwords 
        WHERE breach_count > 0 
        ORDER BY breach_count DESC 
        LIMIT 10
    """)
    top_breached = cursor.fetchall()
    
    conn.close()
    
    return {
        'total_passwords': stats[0],
        'breached_passwords': stats[1],
        'total_breaches': stats[2],
        'breach_history': history[::-1],
        'top_breached': top_breached
    }

@app.route('/')
def dashboard():
    data = get_breach_data()
    return render_template('dashboard.html', data=data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
