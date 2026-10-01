import requests

for i in range(5):
    response = requests.post(
        "http://127.0.0.1:5000/api/failed-login",
        json={
            "source_ip": "192.168.1.50",
            "username": "admin"
        }
    )

    print("Attempt", i + 1, response.json())