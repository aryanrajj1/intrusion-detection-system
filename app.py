from flask import Flask, jsonify, render_template, request
import sqlite3
import threading
import time
from datetime import datetime, timedelta
import psutil

app = Flask(__name__)

DB_NAME = "ids_logs.db"

# =========================
# DETECTION CONFIGURATION
# =========================

WATCHED_PORTS = {
    21,      # FTP
    22,      # SSH
    23,      # Telnet
    3306,    # MySQL
    3389,    # RDP
    5432,    # PostgreSQL
    6379,    # Redis
    8080
}

HIGH_RISK_PORTS = {
    21,
    22,
    23,
    135,
    139,
    445,
    1433,
    3306,
    3389,
    5432,
    6379
}

connection_history = {}


# =========================
# DATABASE
# =========================

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            port INTEGER,
            message TEXT,
            status TEXT DEFAULT 'OPEN'
        )
    """)

    # Add status column if database is old
    columns = conn.execute(
        "PRAGMA table_info(security_events)"
    ).fetchall()

    column_names = [column["name"] for column in columns]

    if "status" not in column_names:
        conn.execute("""
            ALTER TABLE security_events
            ADD COLUMN status TEXT DEFAULT 'OPEN'
        """)

    conn.commit()
    conn.close()


# =========================
# SAVE SECURITY EVENT
# =========================

def save_event(
    event_type,
    severity,
    source_ip,
    port,
    message
):

    conn = get_db()

    conn.execute("""
        INSERT INTO security_events
        (
            timestamp,
            event_type,
            severity,
            source_ip,
            port,
            message,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type,
        severity,
        source_ip,
        port,
        message,
        "OPEN"
    ))

    conn.commit()
    conn.close()
    # =========================
# FAILED LOGIN DETECTION
# =========================

failed_login_attempts = {}

@app.route("/api/failed-login", methods=["POST"])
def failed_login():
    data = request.get_json() or {}

    source_ip = data.get("source_ip", "127.0.0.1")
    username = data.get("username", "unknown")

    now = time.time()

    if source_ip not in failed_login_attempts:
        failed_login_attempts[source_ip] = []

    # Keep attempts from last 60 seconds
    failed_login_attempts[source_ip] = [
        t for t in failed_login_attempts[source_ip]
        if now - t <= 60
    ]

    failed_login_attempts[source_ip].append(now)

    attempts = len(failed_login_attempts[source_ip])

    if attempts >= 5:
        save_event(
            "FAILED LOGIN",
            "HIGH",
            source_ip,
            0,
            f"Multiple failed login attempts detected for user '{username}' ({attempts} attempts)"
        )

        failed_login_attempts[source_ip] = []

        return jsonify({
            "detected": True,
            "severity": "HIGH",
            "attempts": attempts
        })

    return jsonify({
        "detected": False,
        "attempts": attempts
    })


# =========================
# DETECTION ENGINE
# =========================

def detect_connection(source_ip, port):

    now = datetime.now()

    # -------------------------
    # CONNECTION HISTORY
    # -------------------------

    if source_ip not in connection_history:
        connection_history[source_ip] = []

    connection_history[source_ip].append(
        (now, port)
    )

    # Keep only last 30 seconds
    connection_history[source_ip] = [
        item
        for item in connection_history[source_ip]
        if now - item[0] <= timedelta(seconds=30)
    ]

    recent_connections = connection_history[source_ip]

    unique_ports = set(
        item[1]
        for item in recent_connections
    )


    # -------------------------
    # PORT SCAN
    # -------------------------

    if len(unique_ports) >= 8:

        save_event(
            "PORT SCAN",
            "CRITICAL",
            source_ip,
            port,
            "Multiple different destination ports detected from the same source"
        )

        return


    # -------------------------
    # CONNECTION BURST
    # -------------------------

    if len(recent_connections) >= 10:

        save_event(
            "CONNECTION BURST",
            "HIGH",
            source_ip,
            port,
            "Multiple connections detected from the same source"
        )

        return


    # -------------------------
    # HIGH RISK PORT
    # -------------------------

    if port in HIGH_RISK_PORTS:

        save_event(
            "HIGH RISK PORT",
            "HIGH",
            source_ip,
            port,
            f"Connection detected to high-risk port {port}"
        )

        return


    # -------------------------
    # WATCHED PORT
    # -------------------------

    if port in WATCHED_PORTS:

        save_event(
            "WATCHED PORT",
            "MEDIUM",
            source_ip,
            port,
            f"Connection detected to watched port {port}"
        )

        return


    # -------------------------
    # UNUSUAL PORT
    # -------------------------

    if port > 10000:

        save_event(
            "UNUSUAL PORT",
            "LOW",
            source_ip,
            port,
            f"Connection detected on unusual port {port}"
        )


# =========================
# NETWORK MONITOR
# =========================

def monitor_network():

    print("IDS NETWORK MONITOR STARTED")

    previous_connections = set()

    while True:

        try:

            connections = psutil.net_connections(
                kind="inet"
            )

            current_connections = set()

            for connection in connections:

                if not connection.raddr:
                    continue

                try:

                    source_ip = connection.raddr.ip
                    port = connection.raddr.port

                except AttributeError:
                    continue

                connection_id = (
                    source_ip,
                    port
                )

                current_connections.add(
                    connection_id
                )


                # Only detect newly observed connections
                if connection_id not in previous_connections:

                    detect_connection(
                        source_ip,
                        port
                    )


            previous_connections = current_connections

        except Exception as error:

            print(
                "Monitoring error:",
                error
            )

        time.sleep(3)


# =========================
# DASHBOARD
# =========================

@app.route("/")
def dashboard():

    return render_template(
        "dashboard.html"
    )


# =========================
# EVENTS API
# =========================

@app.route("/api/events")
def get_events():

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


    # Severity filter

    if severity != "ALL":

        query += """
            AND severity = ?
        """

        params.append(
            severity
        )


    # Search filter

    if search:

        query += """
            AND (
                source_ip LIKE ?
                OR CAST(port AS TEXT) LIKE ?
                OR event_type LIKE ?
                OR message LIKE ?
            )
        """

        search_value = f"%{search}%"

        params.extend([
            search_value,
            search_value,
            search_value,
            search_value
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


# =========================
# STATISTICS API
# =========================

@app.route("/api/stats")
def get_stats():

    conn = get_db()


    total = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
    """).fetchone()[0]


    critical = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE severity = 'CRITICAL'
    """).fetchone()[0]


    high = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE severity = 'HIGH'
    """).fetchone()[0]


    medium = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE severity = 'MEDIUM'
    """).fetchone()[0]


    low = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE severity = 'LOW'
    """).fetchone()[0]


    open_events = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE status = 'OPEN'
    """).fetchone()[0]


    acknowledged = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE status = 'ACKNOWLEDGED'
    """).fetchone()[0]


    conn.close()


    return jsonify({

        "total": total,

        "critical": critical,

        "high": high,

        "medium": medium,

        "low": low,

        "open": open_events,

        "acknowledged": acknowledged

    })


# =========================
# TOP ATTACKING IPS
# =========================

@app.route("/api/attackers")
def attackers():

    conn = get_db()


    rows = conn.execute("""
        SELECT
            source_ip,
            COUNT(*) AS attacks
        FROM security_events
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY attacks DESC
        LIMIT 10
    """).fetchall()


    conn.close()


    return jsonify([

        {
            "source_ip": row["source_ip"],
            "attacks": row["attacks"]
        }

        for row in rows

    ])


# =========================
# ACKNOWLEDGE EVENT
# =========================

@app.route(
    "/api/events/<int:event_id>/acknowledge",
    methods=["PUT"]
)
def acknowledge_event(event_id):

    conn = get_db()


    conn.execute("""
        UPDATE security_events
        SET status = 'ACKNOWLEDGED'
        WHERE id = ?
    """, (
        event_id,
    ))


    conn.commit()
    conn.close()


    return jsonify({
        "success": True,
        "status": "ACKNOWLEDGED"
    })


# =========================
# DELETE EVENT
# =========================

@app.route(
    "/api/events/<int:event_id>",
    methods=["DELETE"]
)
def delete_event(event_id):

    conn = get_db()


    conn.execute("""
        DELETE FROM security_events
        WHERE id = ?
    """, (
        event_id,
    ))


    conn.commit()
    conn.close()


    return jsonify({
        "success": True
    })


# =========================
# CLEAR ALL EVENTS
# =========================

@app.route(
    "/api/clear",
    methods=["DELETE"]
)
def clear_events():

    conn = get_db()


    conn.execute("""
        DELETE FROM security_events
    """)


    conn.commit()
    conn.close()


    return jsonify({
        "success": True
    })


# =========================
# START APPLICATION
# =========================

if __name__ == "__main__":

    init_db()


    monitor_thread = threading.Thread(
        target=monitor_network,
        daemon=True
    )

    monitor_thread.start()


    print(
        "IDS Dashboard running at "
        "http://127.0.0.1:5000"
    )


    app.run(
        debug=True,
        use_reloader=False
    )