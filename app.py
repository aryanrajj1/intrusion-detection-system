import time
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime
from flask import Flask, render_template, jsonify, request
import psutil

app = Flask(__name__)

DATABASE = "ids_logs.db"

WATCH_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 1433, 3306, 3389, 5432,
    5900, 6379, 8080
}

HIGH_RISK_PORTS = {
    21, 22, 23, 135, 139, 445,
    1433, 3306, 3389, 5900, 6379
}

connection_history = defaultdict(list)
port_history = defaultdict(list)
reported = set()


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            message TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_event(alert):
    conn = get_db()

    conn.execute("""
        INSERT INTO security_events
        (timestamp, event_type, severity, source_ip, port, message)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["time"],
        alert["type"],
        alert["severity"],
        alert["source"],
        alert["port"],
        alert["message"]
    ))

    conn.commit()
    conn.close()


def create_alert(event_type, severity, ip, port, message):
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "severity": severity,
        "source": ip,
        "port": port,
        "message": message
    }


def detect_threats(connections):
    alerts = []
    now = time.time()

    for connection in connections:

        if not connection.raddr:
            continue

        ip = connection.raddr.ip
        port = connection.raddr.port

        # Rule 1: High-risk ports
        if port in HIGH_RISK_PORTS:
            alerts.append(
                create_alert(
                    "HIGH RISK PORT",
                    "HIGH",
                    ip,
                    port,
                    f"Connection detected on high-risk port {port}"
                )
            )

        # Rule 2: Watched ports
        elif port in WATCH_PORTS:
            alerts.append(
                create_alert(
                    "WATCHED PORT",
                    "MEDIUM",
                    ip,
                    port,
                    f"Connection detected to watched port {port}"
                )
            )

        # Rule 3: Unusual ports
        elif port > 10000:
            alerts.append(
                create_alert(
                    "UNUSUAL PORT",
                    "LOW",
                    ip,
                    port,
                    f"Connection detected on unusual port {port}"
                )
            )

        # Rule 4: Connection burst
        connection_history[ip].append(now)

        connection_history[ip] = [
            t for t in connection_history[ip]
            if now - t <= 30
        ]

        if len(connection_history[ip]) >= 10:
            alerts.append(
                create_alert(
                    "CONNECTION BURST",
                    "HIGH",
                    ip,
                    port,
                    "Multiple connections detected from the same source"
                )
            )

        # Rule 5: Port scan pattern
        port_history[ip].append((now, port))

        port_history[ip] = [
            item for item in port_history[ip]
            if now - item[0] <= 30
        ]

        unique_ports = set(
            item[1] for item in port_history[ip]
        )

        if len(unique_ports) >= 8:
            alerts.append(
                create_alert(
                    "PORT SCAN",
                    "CRITICAL",
                    ip,
                    port,
                    "Multiple different destination ports detected from the same source"
                )
            )

    return alerts


def monitor_network():

    while True:

        try:
            connections = psutil.net_connections(
                kind="inet"
            )

            alerts = detect_threats(connections)

            for alert in alerts:

                key = (
                    alert["source"],
                    alert["port"],
                    alert["type"]
                )

                if key not in reported:

                    save_event(alert)
                    reported.add(key)

        except Exception:
            pass

        time.sleep(5)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/events")
def events():

    severity = request.args.get(
        "severity",
        "ALL"
    )

    search = request.args.get(
        "search",
        ""
    ).strip()

    conn = get_db()

    query = """
        SELECT *
        FROM security_events
        WHERE 1=1
    """

    params = []

    if severity != "ALL":

        query += """
            AND severity = ?
        """

        params.append(severity)

    if search:

        query += """
            AND (
                source_ip LIKE ?
                OR event_type LIKE ?
                OR message LIKE ?
                OR CAST(port AS TEXT) LIKE ?
            )
        """

        value = f"%{search}%"

        params.extend([
            value,
            value,
            value,
            value
        ])

    query += """
        ORDER BY id DESC
        LIMIT 100
    """

    rows = conn.execute(
        query,
        params
    ).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.route("/api/stats")
def stats():

    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) FROM security_events"
    ).fetchone()[0]

    critical = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE severity='CRITICAL'"
    ).fetchone()[0]

    high = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE severity='HIGH'"
    ).fetchone()[0]

    medium = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE severity='MEDIUM'"
    ).fetchone()[0]

    low = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE severity='LOW'"
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    })


@app.route(
    "/api/events/<int:event_id>",
    methods=["DELETE"]
)
def delete_event(event_id):

    conn = get_db()

    conn.execute(
        "DELETE FROM security_events WHERE id = ?",
        (event_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })


@app.route(
    "/api/clear",
    methods=["DELETE"]
)
def clear_events():

    conn = get_db()

    conn.execute(
        "DELETE FROM security_events"
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })


if __name__ == "__main__":

    init_database()

    monitor = threading.Thread(
        target=monitor_network,
        daemon=True
    )

    monitor.start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )