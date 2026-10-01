import sqlite3
from datetime import datetime

conn = sqlite3.connect("ids_logs.db")

events = [
    (
        "PORT SCAN",
        "CRITICAL",
        "127.0.0.1",
        445,
        "Multiple different destination ports detected from the same source"
    ),
    (
        "CONNECTION BURST",
        "HIGH",
        "127.0.0.1",
        22,
        "Multiple connections detected from the same source"
    ),
    (
        "WATCHED PORT",
        "MEDIUM",
        "127.0.0.1",
        3306,
        "Connection detected to watched port 3306"
    ),
    (
        "UNUSUAL PORT",
        "LOW",
        "127.0.0.1",
        12000,
        "Connection detected on unusual port 12000"
    )
]

for event in events:
    conn.execute("""
        INSERT INTO security_events
        (timestamp, event_type, severity, source_ip, port, message)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event[0],
        event[1],
        event[2],
        event[3],
        event[4]
    ))

conn.commit()
conn.close()

print("TEST EVENTS INSERTED SUCCESSFULLY")