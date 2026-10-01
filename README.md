# Intrusion Detection System (IDS)

A Python-based Intrusion Detection System designed to monitor network connections, detect suspicious activity, store security events, and display alerts through a real-time web dashboard.

## Features

- Real-time network monitoring
- SOC-style detection engine
- Security event logging
- SQLite database
- Flask web dashboard
- Severity classification
- Critical, High, Medium and Low alerts
- Port scan detection
- Connection burst detection
- High-risk port monitoring
- Watched port detection
- Unusual port detection
- Event search and filtering
- Event deletion
- Clear security logs
- Security statistics
- Detection charts
- Auto-refresh dashboard

## Detection Rules

| Detection Rule | Severity | Description |
|---|---|---|
| Port Scan | CRITICAL | Multiple destination ports detected from the same source |
| Connection Burst | HIGH | Multiple connections detected from the same source |
| High Risk Port | HIGH | Connection detected on a high-risk port |
| Watched Port | MEDIUM | Connection detected on a monitored port |
| Unusual Port | LOW | Connection detected on an unusual high-numbered port |

## Technologies

- Python
- Flask
- SQLite
- psutil
- HTML
- CSS
- JavaScript
- Chart.js

## Project Structure

```text
IDS/
│
├── app.py
├── test_event.py
├── requirements.txt
├── README.md
├── ids_logs.db
│
├── templates/
│   └── dashboard.html
│
└── static/
    ├── style.css
    └── dashboard.js